// 编成 WINDOWS 子系统：双击时不再先弹出黑色控制台窗口再关掉（那一下"黑框一闪"）。
// 命令行子命令（print-mac / logoff / auth）靠 attach_parent_console() 把输出接回
// 调用者的控制台。Linux/macOS 构建不受影响。
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod net;
mod pcapx;
mod packets;
mod eap;
mod args;
mod config;
mod err;
#[cfg(target_os = "windows")]
mod gui;

#[cfg(target_os = "windows")]
use windows::core::{PCSTR, PCWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{BOOL};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOA, CREATE_NO_WINDOW, CreateProcessA};
#[cfg(target_os = "windows")]
use windows::core::PSTR;
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::CREATE_NEW_CONSOLE;

#[cfg(target_os = "linux")]

use std::cell::UnsafeCell;
use std::ffi::CString;
use std::fmt::format;
use std::net::IpAddr;
use std::process::exit;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::mpsc::{RecvError, RecvTimeoutError};
use std::{ptr, thread};
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use clap::Parser;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use daemonize::Daemonize;
use encoding_rs::GBK;
use log::{debug, error, info, warn};
use pcap::{Active, Capture, Device, State};
use pnet::datalink::NetworkInterface;
use crate::args::{EapArgs, EapCommands};
use crate::eap::{Status, CODE_FAILURE, CODE_REQUEST, CODE_SUCCESS, EAP_TYPE_IDENTITY, EAP_TYPE_MD5_CHALLENGE};
use crate::err::EapError;
use crate::pcapx::SharedCapture;

// ===== 默认配置（发布版：不含任何个人信息）=====
// 账号 / 密码 / 网卡一律留空：
//   . GUI 首次打开时输入框为空，由用户填写后保存到同目录 mentorust-gui.ini；
//   . 网卡留空时自动挑选第一张带 10.x 地址的网卡（校园网网段），见 find_nic()。
const DEFAULT_NIC: &str = "";
const DEFAULT_USER: &str = "";
const DEFAULT_PASS: &str = "";
const DEFAULT_DHCP_MODE: u8 = 0;

// ===== 「手动断开」闩锁 =====
//
// 需求：点了「断开」之后，**任何自动路径都不许再把网络连回来**；
// 只有用户再次显式点「连接」（或执行 auth 子命令）才恢复。
// 做法：在 exe 同目录放一个 mentorust.stop 标记文件。
//   · logoff()        → 写入标记
//   · do_connect/连接  → 清除标记
//   · ghost 启动/监督循环/--auto → 发现标记就拒绝联网并退出
// 这样即使开机自启、残留进程、看门狗之类的路径，也不会把手动断开的连接拉回来。
fn stop_flag_path() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("mentorust.stop")))
}

fn stop_flag_set() -> bool {
    stop_flag_path().map(|p| p.exists()).unwrap_or(false)
}

fn set_stop_flag(on: bool) {
    if let Some(p) = stop_flag_path() {
        if on {
            let _ = std::fs::write(&p, "manual disconnect\n");
        } else {
            let _ = std::fs::remove_file(&p);
        }
    }
}

// ===== 日志落盘 =====
//
// ghost 是用 CREATE_NO_WINDOW 拉起来的，stderr 直接丢弃 —— 一旦出现"概率性
// 掉线"这种问题，事后完全无法复盘（这正是前几轮排查困难的原因）。主流客户端
// 都会落盘（锐捷写日志文件，MentoHUST `-b3` 写 /tmp/mentohust.log），这里照做：
// 写 exe 同目录的 mentorust.log，超过 1MB 自动滚动成 mentorust.log.1。
// 同时仍输出到 stderr，前台运行时能立刻看到。
static LOG_FILE: Mutex<Option<File>> = Mutex::new(None);

struct SimpleLogger;

/// 本地时间 HH:MM:SS（本机固定 UTC+8，中国大陆无夏令时，无需时区库）
fn now_hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let local = secs + 8 * 3600;
    format!("{:02}:{:02}:{:02}", (local / 3600) % 24, (local / 60) % 60, local % 60)
}

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!("{} {:<5} {}\n", now_hms(), record.level(), record.args());
        if let Ok(mut guard) = LOG_FILE.lock() {
            if let Some(f) = guard.as_mut() {
                let _ = f.write_all(line.as_bytes());
                let _ = f.flush();
            }
        }
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
    fn flush(&self) {
        if let Ok(mut guard) = LOG_FILE.lock() {
            if let Some(f) = guard.as_mut() {
                let _ = f.flush();
            }
        }
    }
}

/// 初始化日志：落盘到 exe 同目录 mentorust.log（超过 1MB 滚动）
fn init_logging() {
    let path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("mentorust.log")));
    if let Some(p) = path {
        if let Ok(md) = std::fs::metadata(&p) {
            if md.len() > 1_000_000 {
                let _ = std::fs::rename(&p, p.with_extension("log.1"));
            }
        }
        if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
            if let Ok(mut g) = LOG_FILE.lock() {
                *g = Some(f);
            }
        }
    }
    let _ = log::set_logger(&SimpleLogger);
    log::set_max_level(log::LevelFilter::Info);
}

/// 把 stdout/stderr 接回父进程的控制台。
///
/// 整个 exe 编成 WINDOWS 子系统（双击不再闪黑窗），从 bat / cmd 调用时默认
/// 没有可用的标准输出句柄。这里 AttachConsole 到父进程控制台，并且**只在原句柄
/// 无效时**才换成 CONOUT$（输出被重定向到文件/管道时保留原句柄，不影响重定向）。
#[cfg(target_os = "windows")]
fn attach_parent_console() {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Console::{
        AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE,
        STD_OUTPUT_HANDLE,
    };
    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
            return; // 双击启动：本来就没有控制台，正常
        }
        let name: Vec<u16> = "CONOUT$".encode_utf16().chain(std::iter::once(0)).collect();
        let conout = match CreateFileW(
            PCWSTR(name.as_ptr()),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            Default::default(),
            HANDLE(std::ptr::null_mut()),
        ) {
            Ok(h) => h,
            Err(_) => return,
        };
        for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let invalid = match GetStdHandle(which) {
                Ok(h) => h.0.is_null(),
                Err(_) => true,
            };
            if invalid {
                let _ = SetStdHandle(which, conout);
            }
        }
    }
}

fn main() {
    std::env::set_var("RUST_LOG", "info");
    #[cfg(target_os = "windows")]
    attach_parent_console();
    init_logging();

    // Ghost instance: hidden background worker spawned by the launcher.
    // Takes a single-instance lock, then authenticates and keeps the
    // connection alive (heartbeat) until killed or shutdown.
    if std::env::args().any(|a| a == "--ghost") {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
            use windows::Win32::System::Threading::CreateMutexA;
            unsafe {
                let _lock = CreateMutexA(None, false, PCSTR(c"MentorustGhostInstance".as_ptr() as *const u8));
                if GetLastError() == ERROR_ALREADY_EXISTS {
                    warn!("已有后台认证进程在运行，本次启动放弃（避免双心跳）。");
                    return; // another ghost instance is already running
                }
            }
        }
        // 账号密码可由 GUI 通过命令行传入（未传则用内置默认值）
        let argv: Vec<String> = std::env::args().collect();
        let opt = |key: &str| -> Option<String> {
            argv.iter()
                .position(|a| a == key)
                .and_then(|i| argv.get(i + 1))
                .cloned()
        };
        // 用户手动点过「断开」→ 处于"停用"状态，任何自动路径都不许再联网。
        // 必须显式点「连接」（会清掉这个标记）才会重新认证。
        if stop_flag_set() {
            warn!("处于「手动断开」状态（存在 mentorust.stop），本次后台认证已跳过。点「连接」可恢复。");
            return;
        }
        // 没显式传 --gui-nic → 用 GUI 里选过的那张（否则内置默认）
        let nic = opt("--gui-nic")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(saved_nic);
        let user = opt("--gui-user")
            .filter(|s| !s.is_empty())
            .or_else(|| saved_cred("user"))
            .unwrap_or_else(|| DEFAULT_USER.to_string());
        let pass = opt("--gui-pass")
            .filter(|s| !s.is_empty())
            .or_else(|| saved_cred("pass"))
            .unwrap_or_else(|| DEFAULT_PASS.to_string());
        auth(nic, user, pass, DEFAULT_DHCP_MODE);
        return;
    }

    // 静默自动认证（旧的开机自启方式，不开界面）
    if std::env::args().any(|a| a == "--auto") {
        #[cfg(target_os = "windows")]
        run_launcher();
        return;
    }

    // 开机自启动拉起：打开界面；是否顺带自动联网由界面读配置里的「自动连接」决定。
    // 与 `--auto` 的区别：`--startup` 会显示窗口，用户能看见状态、随时改设置。
    if std::env::args().any(|a| a == "--startup") {
        #[cfg(target_os = "windows")]
        {
            gui::set_startup_launch(true);
            gui::run();
        }
        return;
    }

    let args = EapArgs::parse();

    match args.command {
        Some(EapCommands::Auth { nic, username, password, dhcp_mode, background, anti_share }) => {
            // 显式的一次认证请求 → 清除「手动断开」标记
            set_stop_flag(false);
            #[cfg(target_os = "linux")]
            if cfg!(target_os = "linux") {
                if unsafe { libc::geteuid() } != 0 {
                    error!("请使用root权限运行！");
                    exit(-4);
                }
            }

            if background {
                #[cfg(target_os = "windows")]
                no_windows_run(nic, username, password, dhcp_mode);
                #[cfg(target_os = "linux")]
                no_console_run(nic, username, password, dhcp_mode);
                #[cfg(target_os = "macos")]
                no_macos_run(nic, username, password, dhcp_mode);
            } else {
                //thread::sleep(Duration::from_secs(5));
                auth(nic, username, password, dhcp_mode);
            }
        },
        Some(EapCommands::DecodeConfig { path }) => {
            info!("解码配置文件: {}", path);
            eap::utils::decode_config(&path);
        }
        Some(EapCommands::AutoCapture { .. }) => {
            unimplemented!()
        }
        Some(EapCommands::PrintMac) => {
            net::print_all_network_mac();
        }
        Some(EapCommands::Logoff { nic }) => {
            logoff(&nic);
        }
        None => {
            // 双击启动：打开图形界面（账号密码可填，连接/断开按钮）
            #[cfg(target_os = "windows")]
            gui::run();
            #[cfg(not(target_os = "windows"))]
            unimplemented!()
        }
    }
}

// ===== double-click launcher (Windows) =====

/// 返回「任意」一张 10.x 网卡上的 IPv4 地址。
///
/// ⚠️ 不要再拿它做在线判断（见 `campus_online`）。校园 Wi-Fi 也是 10.x，
/// 且 pnet 的枚举顺序里 Wi-Fi 往往排在有线之前 —— 一旦取到 Wi-Fi 地址，
/// DNS 探测就会恒为成功，掉线将被完全掩盖。仅保留作诊断用途。
#[allow(dead_code)]
fn find_campus_ipv4() -> Option<std::net::Ipv4Addr> {
    for inet in pnet::datalink::interfaces() {
        for ip in inet.ips {
            if let IpAddr::V4(v4) = ip.ip() {
                if v4.octets()[0] == 10 {
                    return Some(v4);
                }
            }
        }
    }
    None
}

fn online_check(src: &std::net::Ipv4Addr) -> bool {
    use std::net::UdpSocket;
    // minimal DNS query: A record for "www.com"
    const QUERY: [u8; 25] = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3, b'w', b'w', b'w', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
    ];
    // 多目标冗余：单个 DNS 在高峰期会偶发丢包，凭它一个就判掉线太激进。
    // 任一目标有回包即视为在线；只有全部无回应才算不通。
    for target in ["223.5.5.5:53", "114.114.114.114:53"] {
        let sock = match UdpSocket::bind((src.to_string().as_str(), 0)) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if sock.set_read_timeout(Some(Duration::from_secs(1))).is_err() {
            continue;
        }
        if sock.connect(target).is_err() {
            continue;
        }
        if sock.send(&QUERY).is_err() {
            continue;
        }
        let mut buf = [0u8; 512];
        if sock.recv(&mut buf).is_ok() {
            return true;
        }
    }
    false
}

/// 取「指定网卡」上的 10.x IPv4 地址（认证网卡自己的地址）。
fn campus_ipv4_of(nic_name: &str) -> Option<std::net::Ipv4Addr> {
    let iface = net::get_network_interface_by_name(nic_name)?;
    iface.ips.iter().find_map(|ip| match ip.ip() {
        IpAddr::V4(v4) if v4.octets()[0] == 10 => Some(v4),
        _ => None,
    })
}

/// 认证网卡是否真的能上网：必须用它自己的源地址做 DNS 探测。
///
/// 用「任意 10.x 网卡」判断在线是错的：同时连着校园 Wi-Fi 时，
/// Wi-Fi 会替有线"回答"探测，导致掉线被误判为在线。
fn campus_online(nic_name: &str) -> bool {
    campus_ipv4_of(nic_name)
        .map(|ip| online_check(&ip))
        .unwrap_or(false)
}

/// GUI 里选过的网卡（记在 exe 同目录 `mentorust-gui.ini` 的 `nic=` 行）。
/// 没选过 / 读不出来 → 回退到内置默认网卡。
fn saved_nic() -> String {
    let path = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("mentorust-gui.ini")));
    if let Some(p) = path {
        if let Ok(txt) = std::fs::read_to_string(&p) {
            for line in txt.lines() {
                if let Some(v) = line.strip_prefix("nic=") {
                    let v = v.trim();
                    if !v.is_empty() {
                        return v.to_string();
                    }
                }
            }
        }
    }
    // ini 里没记录 → 自动挑第一张带 10.x 地址的网卡（校园网网段）。
    // 挑不到才回落到内置默认（发布版为空，交由 find_nic 报错提示）。
    if let Ok(devs) = Device::list() {
        if let Some(d) = devs.iter().find(|d| {
            d.addresses
                .iter()
                .any(|a| a.addr.is_ipv4() && a.addr.to_string().starts_with("10."))
        }) {
            return d.name.clone();
        }
    }
    DEFAULT_NIC.to_string()
}

/// 读 exe 同目录 `mentorust-gui.ini` 里的某个键（user / pass）。
/// 发布版不含内置账号，`--ghost` / 开机自启都靠它拿到用户保存的凭据。
#[allow(dead_code)]
fn saved_cred(key: &str) -> Option<String> {
    let path = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("mentorust-gui.ini")));
    let p = path?;
    let txt = std::fs::read_to_string(&p).ok()?;
    let prefix = format!("{}=", key);
    for line in txt.lines() {
        if let Some(v) = line.strip_prefix(&prefix) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn spawn_ghost() {
    // 发布版不含内置账号：优先用 GUI 保存过的（ini），否则用命令行传入的。
    let user = saved_cred("user").unwrap_or_else(|| DEFAULT_USER.to_string());
    let pass = saved_cred("pass").unwrap_or_else(|| DEFAULT_PASS.to_string());
    spawn_ghost_with(&user, &pass, &saved_nic())
}

/// 启动后台认证进程，并带上指定的账号密码 / 网卡
#[cfg(target_os = "windows")]
fn spawn_ghost_with(user: &str, pass: &str, nic: &str) {
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");
    let command_line = CString::new(format!(
        "\"{}\" --ghost --gui-user \"{}\" --gui-pass \"{}\" --gui-nic \"{}\"",
        current_exe.display(),
        user,
        pass,
        nic
    ))
    .expect("Failed to convert command line to CString");
    unsafe {
        let mut startup_info = STARTUPINFOA::default();
        let mut process_info = PROCESS_INFORMATION::default();
        startup_info.cb = size_of::<STARTUPINFOA>() as u32;
        let success = CreateProcessA(
            PCSTR::null(),
            PSTR(command_line.as_ptr() as *mut _),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            PCSTR::null(),
            &mut startup_info,
            &mut process_info,
        );
        if success.is_ok() {
            info!("后台认证进程已启动，PID: {}", process_info.dwProcessId);
        } else {
            error!("启动后台进程失败: {}", windows::core::Error::from_win32());
        }
    }
}

/// 结束除自己以外的所有 mentorust 进程（即后台认证进程）。
///
/// 注意 GUI 进程本身也叫 mentorust.exe，所以必须用 PID 排除自己。
#[cfg(target_os = "windows")]
pub fn kill_ghosts() {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    let self_pid = std::process::id();
    // 不要用 taskkill 子进程：本进程是 GUI 子系统（没有控制台），
    // 任何控制台子进程都会让 Windows 新开一个黑色控制台窗口。
    // 这里直接枚举同名进程并就地结束，连一个子进程都不产生。
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return;
        };
        let mut pe = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                let end = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(pe.szExeFile.len());
                let name = String::from_utf16_lossy(&pe.szExeFile[..end]);
                if pe.th32ProcessID != self_pid && name.eq_ignore_ascii_case("mentorust.exe") {
                    if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, pe.th32ProcessID) {
                        let _ = TerminateProcess(h, 0);
                        let _ = CloseHandle(h);
                    }
                }
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
}

/// 是否已有后台认证进程在运行？
///
/// 用"只探测、不占用"的方式：尝试创建同名互斥体，
/// 返回 ERROR_ALREADY_EXISTS 说明已有进程持有它。
/// 探测完立刻关闭句柄 —— 若这个互斥体是我们刚创建的，关掉即销毁，
/// 不会影响随后启动的真正认证进程。
#[cfg(target_os = "windows")]
pub fn ghost_running() -> bool {
    use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError};
    use windows::Win32::System::Threading::CreateMutexA;
    unsafe {
        match CreateMutexA(None, false, PCSTR(c"MentorustGhostInstance".as_ptr() as *const u8)) {
            Ok(h) => {
                let exists = GetLastError() == ERROR_ALREADY_EXISTS;
                let _ = CloseHandle(h);
                exists
            }
            Err(_) => false,
        }
    }
}

#[cfg(target_os = "windows")]
fn run_launcher() {
    use std::io::Read;

    // 手动断开过 → 不自动联网（--auto 也要遵守"手动断开后不要连回来"）
    if stop_flag_set() {
        info!("处于「手动断开」状态，跳过自动认证。需要联网请双击图标点「连接」。");
        return;
    }

    // 用 GUI 里选定的那张网卡（没选过就是内置默认）
    let nic = saved_nic();

    // already online? nothing to do, just confirm and close
    if campus_online(&nic) {
        info!("[SUCCESS] 校园网已在线，无需重新认证。窗口即将自动关闭...");
        std::thread::sleep(Duration::from_secs(2));
        return;
    }

    info!("正在后台启动认证进程...");
    spawn_ghost();

    // poll until the campus network is reachable, then auto-close
    for i in 1..=20 {
        std::thread::sleep(Duration::from_secs(3));
        if campus_online(&nic) {
            info!("[SUCCESS] 认证成功，已联网！窗口即将自动关闭，认证进程将在后台保持在线。");
            std::thread::sleep(Duration::from_secs(2));
            return;
        }
        info!("等待认证完成... ({}/20)", i);
    }

    error!("[FAILED] 认证超时！请检查：1) Npcap 已安装 2) 网卡GUID配置 3) 账号密码。按回车键退出...");
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
}

/// 主动下线：先停掉后台认证进程，再向认证服务器发送 EAPOL-Logoff 注销会话
fn logoff(nic_name: &str) {
    // 0. 先立「手动断开」标记：从此任何自动路径都不允许再联网，
    //    必须显式点「连接」才会清除这个标记。这是"手动断开后不要自动连回去"的保证。
    set_stop_flag(true);

    // 1. 结束其他后台认证实例（跳过自己）。
    //    这里不 spawn taskkill 子进程：GUI 进程没有控制台，
    //    控制台子进程会让 Windows 弹出黑色窗口。kill_ghosts 是就地实现。
    kill_ghosts();

    // 2. 找到认证网卡
    let devices = match Device::list() {
        Ok(d) => d,
        Err(e) => {
            error!("枚举网卡失败: {:?}", e);
            return;
        }
    };
    let dev = if nic_name.is_empty() {
        devices
            .iter()
            .find(|d| d.name == DEFAULT_NIC)
            .or_else(|| {
                devices.iter().find(|d| {
                    d.addresses.iter().any(|a| a.addr.is_ipv4() && a.addr.to_string().starts_with("10."))
                })
            })
            .cloned()
    } else {
        devices.iter().find(|d| d.name == nic_name).cloned()
    };
    let Some(dev) = dev else {
        error!("未找到认证网卡！请检查网线或用 -n 指定网卡。");
        return;
    };

    let Some(inet) = net::get_network_interface_by_name(&dev.name) else {
        error!("未找到网卡的MAC地址: {}", dev.name);
        return;
    };
    let mac = inet.mac.unwrap().to_string().to_lowercase();
    let mut local_mac = [0u8; 6];
    hex::decode_to_slice(mac.replace(":", ""), &mut local_mac).unwrap();

    // 3. 打开抓包句柄并发送 EAPOL-Logoff（标准组播 + 锐捷私有地址双保险）
    let mut cap = match Capture::from_device(dev)
        .unwrap()
        .immediate_mode(true)
        .timeout(1000)
        .open()
    {
        Ok(c) => c,
        Err(e) => {
            error!("打开网卡失败: {:?}（Npcap 是否已安装？）", e);
            return;
        }
    };

    for dest in [[0x01u8, 0x80, 0xc2, 0x00, 0x00, 0x03], [0x01, 0xd0, 0xf9, 0x00, 0x00, 0x03]] {
        let mut frame = Vec::with_capacity(18);
        frame.extend_from_slice(&dest);
        frame.extend_from_slice(&local_mac);
        frame.extend_from_slice(&0x888e_u16.to_be_bytes());
        frame.push(0x01); // version 802.1X-2001
        frame.push(0x02); // type EAPOL-Logoff
        frame.extend_from_slice(&0x0000_u16.to_be_bytes());
        match cap.sendpacket(frame.as_slice()) {
            Ok(_) => info!("已向 {:02x?} 发送 EAPOL-Logoff", dest),
            Err(e) => error!("发送下线包失败: {}", e),
        }
    }

    info!("[LOGOFF] 下线请求已发送，校园网会话已注销。重新联网请双击 mentorust.exe。");
}

#[cfg(target_os = "linux")]
fn no_console_run(
    nic_name: String,
    username: String,
    password: String,
    dhcp_mode: u8
) {
    let out_file = std::env::var("MENTORUST_OUT_FILE")
        .unwrap_or("/tmp/mentorust.out".to_string());
    let pid_file = std::env::var("MENTORUST_PID_FILE")
        .unwrap_or("/tmp/mentorust.pid".to_string());

    let stdout = File::create(out_file).unwrap();
    let stderr = stdout.try_clone().unwrap();

    // working_directory fetch
    let current_direction = std::env::current_dir().unwrap();

    let daemonize = Daemonize::new()
        .pid_file(pid_file)
        .chown_pid_file(true)
        .working_directory(current_direction)
        .umask(0o777)
        .stdout(stdout)
        .stderr(stderr)
        .privileged_action(|| "Executed before drop privileges");

    match daemonize.start() {
        Ok(_) => {
            info!("程序将作为系统守护进程切换到后台运行");
            auth(nic_name, username, password, dhcp_mode);
        },
        Err(e) => error!("后台运行失败, {}", e),
    }
}

#[cfg(target_os = "windows")]
fn no_windows_run(
    nic_name: String,
    username: String,
    password: String,
    dhcp_mode: u8
) {
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");
    let command_line = CString::new(format!("{} auth -n \"{}\" -d {} -u {} -p {}", current_exe.display(), nic_name, dhcp_mode, username, password))
        .expect("Failed to convert command line to CString");

    //info!("Cmd: {:?}", command_line.to_string_lossy());

    unsafe {
        let mut startup_info = STARTUPINFOA::default();
        let mut process_info = PROCESS_INFORMATION::default();
        startup_info.cb = size_of::<STARTUPINFOA>() as u32;

        let success = CreateProcessA(
            PCSTR::null(),
            PSTR(command_line.as_ptr() as *mut _),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None, // todo(后台进程环境变量丢失?)
            PCSTR::null(),
            &mut startup_info,
            &mut process_info,
        );

        if success.is_ok() {
            debug!("CreateProcessA success");
            let pid = process_info.dwProcessId;
            info!("进程已切换到后台运行，PID: {}", pid);
            exit(pid as i32);
        } else {
            error!("创建后台进程失败 无法后台运行: {}", windows::core::Error::from_win32());
        }
    }
}

#[cfg(target_os = "macos")]
fn no_macos_run(
    nic_name: String,
    username: String,
    password: String,
    dhcp_mode: u8
){
    let out_file = std::env::var("MENTORUST_OUT_FILE")
        .unwrap_or("/tmp/mentorust.out".to_string());
    let pid_file = std::env::var("MENTORUST_PID_FILE")
        .unwrap_or("/tmp/mentorust.pid".to_string());

    let stdout = File::create(&out_file).unwrap();
    let stderr = stdout.try_clone().unwrap();

    let current_direction = std::env::current_dir().unwrap();

    let daemonize = Daemonize::new()
        .pid_file(pid_file)
        .chown_pid_file(true)
        .working_directory(current_direction)
        .umask(0o777)
        .stdout(stdout)
        .stderr(stderr)
        .privileged_action(|| "Executed before drop privileges");

    match daemonize.start() {
        Ok(_) => {
            info!("程序已在 macOS 上作为守护进程运行");
            auth(nic_name, username, password, dhcp_mode);
        }
        Err(e) => error!("macOS 后台运行失败: {}", e),
    }
}


fn auth(
    nic_name: String,
    username: String,
    password: String,
    dhcp_mode: u8
) {
    let Some(nic) = find_nic(&nic_name) else {
        return;
    };
    info!("找到认证服务器或WAN网卡: {:?}", nic.desc.as_ref().unwrap_or(&nic.name));
    let Some(inet) = net::get_network_interface_by_name(&nic.name) else {
        error!("未找到网卡({})的MAC地址，请检查网卡名称是否正确！", nic.name);
        return;
    };

    let mut ipv4 = [0u8; 4];
    let mut ipv6 = [0u8; 16];

    for ip in inet.ips {
        match ip.ip() {
            IpAddr::V4(v4) => {
                ipv4 = v4.octets()
            }
            IpAddr::V6(v6) => {
                ipv6 = v6.to_bits().to_be_bytes()
            }
        }
    }
    let mac = inet.mac.unwrap().to_string().to_lowercase();
    if mac.len() != 17 {
        error!("MAC地址({})格式错误，请检查MAC地址是否正确！", mac);
        return;
    }
    info!("网卡({})IPv4地址: {:?}", nic.desc.as_ref().unwrap_or(&nic.name), ipv4);
    info!("网卡({})IPv6地址: {:?}", nic.desc.as_ref().unwrap_or(&nic.name), ipv6);
    info!("网卡({})MAC地址: {:?}", nic.desc.as_ref().unwrap_or(&nic.name), mac);
    let cap = match open_pcap(nic.clone(), &mac) {
        Err(e) => {
            error!("监听网卡数据包失败: {:?}", e);
            return;
        }
        Ok(cap) => {
            cap
        }
    };
    let cap = SharedCapture::new(cap, nic.clone(), mac.clone());

    let mut local_mac = [0u8; 6];
    let mut dest_mac = if dhcp_mode == 1 {
        [0x01, 0xd0, 0xf9, 0x00, 0x00, 0x03]
    } else {
        [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]
    };
    hex::decode_to_slice(mac.replace(":", ""), &mut local_mac).unwrap();

    let receiver = start_loop(cap.clone(), ipv4, ipv6); // 开始监听
    // 发包走独立句柄（nic），与抓包句柄解耦，避免被长时间阻塞的收包路径饿死
    let packet_sender = spawn_packet_sender(cap.clone(), nic, local_mac, username, password); // 发送数据包

    if dhcp_mode == 3 {
        // 原实现是 panic!（release 下 panic='abort'，进程会直接消失），
        // 改成只告警并按默认模式继续，避免一个配置项把客户端搞挂。
        warn!("暂不支持『认证前 DHCP』模式(dhcp_mode=3)，按默认模式继续。");
    }

    // ================= 监督循环（状态机版） =================
    //
    // 参照 MentoHUST / 锐捷官方客户端的做法，把「认证中」与「已授权」严格分开。
    // 这是修「只连有线也会概率断网」的核心：
    //
    //   · 认证中 (phase_auth = true)：**不做 ping 探测**。只等服务器回应，超过
    //     AUTH_TIMEOUT（对应 MentoHUST -t，默认 8s）仍无回应才重发 EAPOL-Start；
    //     服务器明确拒绝后按 FAIL_WAIT（对应 -r，默认 15s）退避、指数增长。
    //     —— 旧实现是无脑 ping 探测：EAP 握手本来就要 4~9 秒，这期间探测必然
    //     不通，于是握手还没结束就又发一个 EAPOL-Start，同一个 MAC 上并行跑两轮
    //     认证，服务器极易判"用户冲突"把会话踢掉 → 概率性断网。
    //     （_diag/ghost3.log 里能直接看到 id=1/2 与 id=3/4 两轮握手在并行。）
    //
    //   · 已授权 (phase_auth = false)：才做 ping 探测（对应 -o）。连续
    //     OFFLINE_STRIKES 次不通才判定掉线并重新认证；但只要服务器明确发来
    //     "下线/重新认证"通知，就**立即**重连，不等探测。
    //
    //   · 用户点「断开」→ 写入 mentorust.stop，本循环发现后立刻退出，
    //     **绝不**把网络自动连回来。
    const TICK_AUTH: Duration = Duration::from_secs(1);
    const TICK_ONLINE: Duration = Duration::from_secs(5);
    const AUTH_TIMEOUT: Duration = Duration::from_secs(8);    // -t 认证超时
    const FAIL_WAIT: Duration = Duration::from_secs(15);      // -r 失败等待
    const FAIL_WAIT_MAX: Duration = Duration::from_secs(120);
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);
    const OFFLINE_STRIKES: u32 = 6;   // 连续 6 次探测不通（约 30s）才判定掉线
    const REOPEN_AFTER: u32 = 20;     // 持续不通约 1 分钟 → 重开网卡句柄
    // 认证成功后的「稳定期」：这段时间 DHCP 续约 / 接入控制尚未生效，
    // 网卡可能还挂着 169.254（APIPA）或 NAT 会话未建立 —— 此时探测必然假失败。
    // 期内即使探测不通也不计 strike，避免「刚连上就被判掉线 -> 强制重认证
    // -> 又断流」的抖动循环。
    const AUTH_SETTLE: Duration = Duration::from_secs(20);

    let mut phase_auth = true;                 // true = 认证中, false = 已授权
    let mut last_server = Instant::now();      // 最近一次收到服务器回应
    let mut retry_at = Instant::now();         // 退避期的"可重试时刻"
    let mut backoff = FAIL_WAIT;
    let mut last_heartbeat = Instant::now();
    let mut offline_strikes: u32 = 0;
    let mut last_reopen = Instant::now();
    let mut settle_until = Instant::now() + AUTH_SETTLE;   // 稳定期截止时刻

    // 开局：发一次 EAPOL-Start（走独立发包句柄，不经抓包锁）
    let _ = packet_sender.send(Status::StartAuth { dest_mac });

    loop {
        // 用户中途点了「断开」→ 立刻停手（手动断开后不自动联网）
        if stop_flag_set() {
            info!("检测到「手动断开」标记，认证进程退出（不会自动重连）。");
            exit(0);
        }

        let tick = if phase_auth { TICK_AUTH } else { TICK_ONLINE };
        match receiver.recv_timeout(tick) {
            Ok(Status::Reconnect) => {
                // 服务器明确要求重认证 → 立即重连，不等探测
                warn!("服务器要求重新认证，正在立即重连...");
                phase_auth = true;
                last_server = Instant::now();
                retry_at = Instant::now();
                backoff = FAIL_WAIT;
                offline_strikes = 0;
                let _ = packet_sender.send(Status::ProbeStartAuth { dest_mac });
            }
            Ok(Status::AuthFailed { reason }) => {
                error!("{}（{} 秒后重试）", reason, backoff.as_secs());
                phase_auth = true;
                offline_strikes = 0;
                last_server = Instant::now();
                retry_at = Instant::now() + backoff;
                backoff = (backoff * 2).min(FAIL_WAIT_MAX);
            }
            Ok(status) => {
                let mut send_heartbeat_now = false;
                if let Status::AuthSuccess { dest_mac: new_dest_mac, .. } = status {
                    dest_mac = new_dest_mac;
                    phase_auth = false;
                    offline_strikes = 0;
                    backoff = FAIL_WAIT;
                    retry_at = Instant::now();
                    last_heartbeat = Instant::now();
                    settle_until = Instant::now() + AUTH_SETTLE;
                    // 认证刚成功就立刻补一个心跳：锐捷交换机/BRAS 依赖 0xBF 心跳
                    // 来激活并维持数据通路，越早发越好。
                    //
                    // 但它必须排在 AuthSuccess **之后**入队：心跳要用成功包里的
                    // 种子，而 packet_sender 只有先收到 AuthSuccess 才拿得到种子。
                    // 以前这里先发心跳，导致首帧只能走固定模板。
                    send_heartbeat_now = true;
                }
                if matches!(status, Status::EapRequestIdentity { .. } | Status::EapRequestPassword { .. }) {
                    last_server = Instant::now();
                }
                let _ = packet_sender.send(status);
                if send_heartbeat_now {
                    let _ = packet_sender.send(Status::Heartbeat { dest_mac });
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                error!("认证器状态接收器已断开，请检查认证器状态接收器是否正常！");
                exit(-2);
            }
            Err(RecvTimeoutError::Timeout) => {}
        }

        if phase_auth {
            // 认证中：只按 -t 超时重发 EAPOL-Start，**绝不** ping 探测
            if Instant::now() >= retry_at && last_server.elapsed() >= AUTH_TIMEOUT {
                warn!("认证无回应（{}秒），重新寻找认证服务器...", AUTH_TIMEOUT.as_secs());
                let _ = packet_sender.send(Status::ProbeStartAuth { dest_mac });
                last_server = Instant::now();
            }
        } else {
            // 已授权：用「认证网卡自己」的地址探测（避免被同网段其它网卡"代答"）
            // 认证成功后的稳定期内直接视为在线，不做掉线判定（DHCP/NAT 未就绪）。
            let online = campus_online(&nic_name) || Instant::now() < settle_until;

            // 心跳与探测**解耦**：心跳是会话保活用的，必须无条件按周期发送。
            // 之前把心跳塞在 online 分支里 -> 一旦探测假失败就再也不发心跳，
            // 会话彻底失去保活，表现为「掉线后永远回不来」。
            if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
                let _ = packet_sender.send(Status::Heartbeat { dest_mac });
                last_heartbeat = Instant::now();
            }

            if online {
                if offline_strikes > 0 {
                    info!("校园网已恢复在线。");
                    offline_strikes = 0;
                }
            } else {
                offline_strikes = offline_strikes.saturating_add(1);
                if offline_strikes == 1 {
                    warn!("探测到有线校园网不通，继续观察（连续 {} 次不通才判定掉线）...", OFFLINE_STRIKES);
                }

                // 长时间不通 → 重开网卡句柄（网卡复位 / 驱动异常后自愈）
                if offline_strikes >= REOPEN_AFTER && last_reopen.elapsed() >= Duration::from_secs(60) {
                    warn!("持续掉线，尝试重新打开网卡句柄...");
                    match cap.reopen() {
                        Ok(_) => info!("网卡句柄已重新打开，继续重连。"),
                        Err(e) => warn!("重开网卡句柄失败: {}", e),
                    }
                    last_reopen = Instant::now();
                }

                if offline_strikes >= OFFLINE_STRIKES {
                    warn!("确认已掉线，立即重新认证...");
                    phase_auth = true;
                    last_server = Instant::now();
                    retry_at = Instant::now();
                    offline_strikes = 0;
                    let _ = packet_sender.send(Status::ProbeStartAuth { dest_mac });
                }
            }
        }
    }
}

/// 打开一个**仅用于发包**的网卡句柄：不加 BPF 过滤、不读包。
fn open_tx_pcap(dev: Device) -> Result<Capture<Active>, EapError> {
    Ok(Capture::from_device(dev)?
        .immediate_mode(true)
        .snaplen(2048)
        .promisc(false)
        .timeout(1000)
        .open()?)
}

fn spawn_packet_sender(
    sc: Arc<SharedCapture>,
    dev: Device,
    local_mac: [u8; 6],
    username: String,
    password: String,
) -> std::sync::mpsc::Sender<Status> {
    let (sender, mut receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        // 发包使用**独立**的网卡句柄，绝不与抓包线程共用同一个句柄。
        //
        // 原因（实测）：抓包线程在没有匹配包时会长时间阻塞在 `for_each` 里
        // 并一直持有共用句柄的那把锁 —— BPF 过滤后 EAPOL 包极稀疏，一次阻塞
        // 能长达数分钟。共用句柄时发包线程永远抢不到锁，心跳 / 重新认证全部
        // 发不出去；现象就是进程日志一直刷"正在重新认证"，但网线上一个 EAPOL
        // 帧都没有，掉线后再也回不来。独立句柄后收发彻底解耦。
        //
        // 出错只记日志、置空句柄，下次发包时自动重建；绝不 panic
        // （release 是 panic=abort，一次 panic 会让整个进程消失、心跳中断）。
        let mut tx: Option<Capture<Active>> = match open_tx_pcap(dev.clone()) {
            Ok(c) => Some(c),
            Err(e) => {
                warn!("打开发包句柄失败（将在下次发包时重试）: {:?}", e);
                None
            }
        };
        let mut send = |pkt: &[u8]| {
            if tx.is_none() {
                tx = open_tx_pcap(dev.clone()).ok();
            }
            match tx.as_mut() {
                Some(c) => {
                    if let Err(e) = c.sendpacket(pkt) {
                        warn!("发送数据包失败，将重建发包句柄后重试: {}", e);
                        tx = None;
                    }
                }
                None => warn!("发包句柄暂不可用（下次发包时重建）"),
            }
        };
        // 锐捷心跳种子：认证成功后从成功包里解出，每次重认证都重置序号。
        let mut echo: Option<packets::EchoState> = None;
        loop {
            let status = match receiver.recv() {
                Ok(status) => status,
                Err(_) => {
                    break
                }
            };
            match status {
                // 心跳只是保活，不代表认证阶段变化，不写 sc.status()。
                Status::Heartbeat { .. } => {}
                // 其余事件（含 ProbeStartAuth / Reconnect）都要记录：start_loop 用
                // sc.status() 判断"失败包"的含义。以前失败会让进程 exit，所以不敢
                // 记录 ProbeStartAuth；现在失败统一转 AuthFailed 交给监督循环退避
                // 重试，记录它是安全的 —— 而且必须记，否则重连途中收到失败包会被
                // 误判成"被踢下线"，进入没有退避的紧凑重试循环。
                _ => {
                    sc.set_status(status);
                }
            }
            match status {
                Status::WaitingLoop => panic!("Error: WaitingLoop"), // waiting_loop should not be sent
                Status::StartAuth { dest_mac } => {
                    // 启动/首次认证前也先清一次旧会话：上一个进程被强杀时
                    // BRAS 上可能残留半开会话，不 Logoff 就会"认证成功但数据不通"。
                    let logoff = packets::build_logoff_packet(&dest_mac, &local_mac);
                    send(logoff.as_slice());
                    thread::sleep(Duration::from_millis(300));
                    info!("寻找认证服务器...");
                    let packet = packets::build_hello_packet(
                        &dest_mac,
                        &local_mac,
                    );
                    send(packet.as_slice());
                }
                Status::ProbeStartAuth { dest_mac } => {
                    // 关键修复：重认证前先发 EAPOL-Logoff，清掉 BRAS 上的旧会话。
                    // 只发 EAPOL-Start 清不掉卡住的半开会话 —— 实测会死锁在
                    // "认证成功但数据面被丢弃"的 30s 循环里；而用户手动
                    // 「断开(Logoff) + 连接」却能立刻恢复。这里自动复刻那一步。
                    let logoff = packets::build_logoff_packet(&dest_mac, &local_mac);
                    send(logoff.as_slice());
                    thread::sleep(Duration::from_millis(300));
                    send(logoff.as_slice());
                    thread::sleep(Duration::from_millis(300));
                    info!("重新认证：寻找认证服务器...");
                    let packet = packets::build_hello_packet(
                        &dest_mac,
                        &local_mac,
                    );
                    send(packet.as_slice());
                }
                Status::EapRequestIdentity { dest_mac, ipv4, ipv6, id } => {
                    info!("发送用户名到认证服务器(mac = {}, id = {})...", dest_mac.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(":"), id);
                    let packet = packets::build_identity_packet(&dest_mac, &local_mac, &ipv4, &ipv6, username.as_str(), id);
                    send(packet.as_slice());
                }
                Status::EapRequestPassword { dest_mac, ipv4, ipv6, id, seed, seed_len } => {
                    info!("发送密码到认证服务器(mac = {}, id = {}, seed_len = {})...", dest_mac.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(":"), id, seed_len);
                    let packet = packets::build_password_packet(&dest_mac, &local_mac, &ipv4, &ipv6, username.as_str(), password.as_str(), id, &seed[0..seed_len as usize]);
                    send(packet.as_slice());
                }
                Status::AuthSuccess { echo_key, .. } => {
                    info!("认证成功...欢迎来到互联网世界！");
                    match echo_key {
                        Some(k) => {
                            info!("已解出锐捷心跳种子 echo_key={:#010x}，心跳将按序号递增发送", k);
                            echo = Some(packets::EchoState::new(k));
                        }
                        None => {
                            warn!("成功包里没取到心跳种子，心跳退回固定模板：会话仍可能每 60 分钟超时一次");
                            echo = None;
                        }
                    }
                }
                Status::Reconnect => {}
                Status::AuthFailed { .. } => {
                    // 失败重试由监督循环统一退避（带日志），这里不做事
                }
                Status::Logoff => {
                    exit(0);
                }
                Status::Heartbeat { dest_mac } => {
                    let packet = packets::build_heartbeat_packet(&dest_mac, &local_mac, echo.as_mut());
                    send(packet.as_slice());
                }
            }
        }
    });
    sender
}

fn start_loop(sc: Arc<SharedCapture>, ipv4: [u8; 4], ipv6: [u8; 16]) -> std::sync::mpsc::Receiver<Status> {
    let (sender, receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        loop {
            if sc.status() == Status::Logoff {
                break
            }
            let mut guard = sc.lock_cap();
            let cap = &mut *guard;
            // 注意：immediate mode + BPF 过滤下，`pcap_loop` 在没有匹配包时
            // 不会因读超时返回，会一直阻塞（传 None 还是 Some(1) 都一样，实测过），
            // 因此抓包线程会长时间持有这把锁 —— 这正是发包必须用**独立句柄**
            // 的原因（见 spawn_packet_sender）。这里传 Some(1) 只为：一旦有包或
            // 句柄出错就尽快回来，便于检查退出条件。
            let cap_result = cap.for_each(Some(1), |packet| {
                let data = packet.data;
                // ⚠️ 必须自己做长度校验：release 是 panic='abort'，任何一次越界索引
                // 都会让**整个进程（含心跳）当场消失** —— 现象就是"概率性掉线"，
                // 而且单实例锁还残留着（=> "要先断开才能连接"）。
                // EAPOL 帧长度差别极大：EAPOL-Start / Logoff 只有 18 字节，
                // 下面的解析却要读到 data[24 + seed_len]，所以逐段检查。
                if data.len() < 14 {
                    return;
                }
                if data[12] != 0x88 || data[13] != 0x8e {
                    return;
                }
                let dest_mac = [data[6], data[7], data[8], data[9], data[10], data[11]];
                // EAP 报文头位于以太头(14) + EAPOL 头(4) 之后
                const EAP_OFF: usize = 18;
                if data.len() < EAP_OFF + 5 {
                    // 纯 EAPOL 控制帧（Start / Logoff / Key），没有 EAP 载荷，忽略
                    return;
                }
                let code = data[EAP_OFF];
                let id = data[EAP_OFF + 1];
                let eap_type = data[EAP_OFF + 4];

                if code == CODE_REQUEST && eap_type == EAP_TYPE_IDENTITY {
                    if sender.send(Status::EapRequestIdentity {
                        dest_mac, ipv4, ipv6, id,
                    }).is_err() {
                        return;
                    }
                } else if code == CODE_REQUEST && eap_type == EAP_TYPE_MD5_CHALLENGE {
                    let seed_len = data[EAP_OFF + 5] as usize;
                    if seed_len > 128 || data.len() < EAP_OFF + 6 + seed_len {
                        warn!("收到异常长度的 MD5 Challenge 包（len={}，seed_len={}），已忽略", data.len(), seed_len);
                        return;
                    }
                    let mut seed = [0u8; 128];
                    seed[0..seed_len].copy_from_slice(&data[EAP_OFF + 6..EAP_OFF + 6 + seed_len]);
                    if sender.send(Status::EapRequestPassword {
                        dest_mac, ipv4, ipv6, id,
                        seed_len: seed_len as u8,
                        seed,
                    }).is_err() {
                        return;
                    }
                } else if code == CODE_SUCCESS {
                    // 系统公告藏在锐捷私有扩展里，偏移是硬编码的 —— 全部做边界检查
                    if data.len() > 0x1c {
                        let offset = 0x1c + data[0x1b] as usize + 0x69 + 39;
                        if offset < data.len() {
                            let raw_len = data[offset - 1] as usize;
                            let len = if raw_len < 2 {
                                0
                            } else {
                                (raw_len - 2).min(data.len() - offset)
                            };
                            if len > 0 {
                                let msg = GBK.decode(&data[offset..offset + len]).0;
                                if msg.starts_with("\n") || msg.starts_with("\r") {
                                    info!("系统公告：{}", msg)
                                } else {
                                    info!("系统公告：\n{}", msg)
                                }
                            }
                        }
                    }
                    let echo_key = packets::extract_echo_key(data);
                    if sender.send(Status::AuthSuccess { dest_mac, echo_key }).is_err() {
                        return;
                    }
                } else if code == CODE_FAILURE {
                    if data.len() > 0x1c {
                        let len = data[0x1b] as usize;
                        if len > 0 && 0x1c + len <= data.len() {
                            let msg = GBK.decode(&data[0x1c..0x1c + len]).0;
                            error!("系统提示：{}", msg);
                        }
                    }
                    // ⚠️ 不再 exit()：一次次生失败就让整个进程消失，正是"概率断网"和
                    // "要先断开才能连接"的来源之一。改为把失败原因带回监督循环，
                    // 由它按 MentoHUST `-r` 的语义退避重试。
                    let reason: &'static str = match sc.status() {
                        Status::Logoff => {
                            exit(0);
                        }
                        // 已授权状态下收到失败包 = 被服务器踢下线 → 立即重连，不等探测
                        Status::AuthSuccess { .. } => {
                            warn!("报错预测：网络掉线或被踢下线...正在尝试重新连接...");
                            if sender.send(Status::Reconnect).is_err() {
                                return;
                            }
                            return;
                        }
                        // EAPOL-Logoff 清理旧会话后，交换机通常回一个 Failure（正常瞬态）；
                        // 刚发出 EAPOL-Start 也还没进入身份交换 —— 都不算真正失败。
                        // 直接忽略，交给认证超时逻辑自然重试，别弹"认证失败"吓人。
                        Status::StartAuth { .. } | Status::ProbeStartAuth { .. } => {
                            return;
                        }
                        Status::Heartbeat { .. } | Status::AuthFailed { .. } => "认证失败",
                        Status::EapRequestIdentity { .. } => {
                            "认证失败：用户名为空/错误，或锐捷私有扩展校验不通过"
                        }
                        Status::EapRequestPassword { .. } => {
                            "认证失败：账号密码错误，或 MAC 地址已被绑定"
                        }
                        _ => "认证失败：找不到认证服务器（请检查网线、是否选对网卡）",
                    };
                    if sender.send(Status::AuthFailed { reason }).is_err() {
                        return;
                    }
                } else if option_env!("MENTORUST_DEBUG") == Some("1") {
                    warn!("Pcap loop: Unknown packet: {:?}", hex::encode(data));
                }
            });
            if cap_result.is_err() {
                // 句柄异常时不要 100% 忙等空转；随后 reopen 逻辑会尝试自愈。
                thread::sleep(Duration::from_millis(200));
            }
        }

    });
    receiver
}

fn open_pcap(
    nic: Device,
    mac: &str
) -> Result<Capture<Active>, EapError> {
    let mut cap = Capture::from_device(nic)?
        .immediate_mode(true)
        .snaplen(2048)
        .promisc(false)
        .timeout(1000)
        .buffer_size(1_000_000)
        .open()?;
    // 除标准 PAE 组播 01:80:c2:00:00:03，还要收锐捷私有组播 01:d0:f9:00:00:03。
    // 漏掉它会导致服务器用私有多播发来的重认证/下线请求收不到 —— 又是"概率性掉线"。
    let rule = format!(
        "ether proto 0x888e and (ether dst {} or ether dst 01:80:c2:00:00:03 or ether dst 01:d0:f9:00:00:03) and not ether src {}",
        mac, mac
    );
    cap.filter(&rule, false).map_err(|e|
        panic!("Error setting filter: {:?}", e)
    ).unwrap();
    Ok(cap)
}

fn find_nic(nic: &str) -> Option<Device> {
    let devices = Device::list()
        .map_err(|e| panic!("Error listing devices: {:?}", e))
        .unwrap();

    if nic.is_empty() {
        info!("未指定网卡，寻找认证服务器以及WAN网卡中...");
        let dev = devices.iter().filter(|dev| {
            !dev.addresses.is_empty() && dev.addresses.iter().any(|addr| addr.addr.is_ipv4() && addr.addr.to_string().starts_with("10."))
        }).collect::<Vec<_>>();

        if dev.is_empty() {
            error!("未找到认证服务器或WAN网卡，没有找到`10.x.x.x`IP的网卡，请手动指定网卡！");
            let names = devices
                .iter()
                .map(|dev| dev.name.clone())
                .collect::<Vec<_>>()
                .join("\n");
            error!("当前网卡列表: \n{}", names);
            return None;
        }

        if dev.len() == 1 {
            Some(dev[0].clone())
        } else {
            if cfg!(target_os = "linux") {
                info!("存在多个`10.x.x.x`IP的网卡，优先匹配`en`开头的网卡！");
                let Some(en) = dev.iter().find(|dev| dev.name.starts_with("en") || dev.name.starts_with("eth")).cloned() else {
                    error!("未找到认证服务器或WAN网卡，没有符合预设的网卡，请手动指定网卡！");
                    let names = devices
                        .iter().map(|dev| dev.name.clone())
                        .collect::<Vec<_>>()
                        .join(", ");
                    error!("当前网卡列表: {}", names);
                    return None;
                };
                return Some(en.clone());
            }
            error!("未找到认证服务器或WAN网卡，没有符合预设的网卡，请手动指定网卡！");
            let names = devices
                .iter().map(|dev| dev.name.clone())
                .collect::<Vec<_>>()
                .join("\n");
            error!("当前网卡列表: {}", names);
            None
        }
    } else {
        let Some(nic) = devices.iter().find(|dev| dev.name == nic) else {
            error!("未找到指定的网卡({})，请检查网卡名称是否正确！", nic);
            let names = devices
                .iter().map(|dev| dev.name.clone())
                .collect::<Vec<_>>()
                .join("\n");
            error!("当前网卡列表: {}", names);
            return None;
        };
        Some(nic.clone())
    }
}
