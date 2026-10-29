// 编成 WINDOWS 子系统：双击时不再先弹出黑色控制台窗口再关掉（那一下"黑框一闪"）。
// 命令行子命令（print-mac / logoff / auth）靠 attach_parent_console() 把输出接回
// 调用者的控制台。Linux/macOS 构建不受影响。
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod net;
mod dhcp;
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
/// 「手动断开」标记的**权威路径**：%LOCALAPPDATA%\mentorust\mentorust.stop
///
/// 原来用 `current_exe().parent()`，而机器上有三份 exe（工程根 / portable/ /
/// target\release\）→ 三个互相独立的标记文件，在 A 目录断开、B 目录启动
/// 完全无效。改为固定路径后所有副本共享同一个闩锁。
fn stop_flag_path() -> Option<std::path::PathBuf> {
    let base = std::env::var("LOCALAPPDATA")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var("APPDATA").ok().map(std::path::PathBuf::from))?;
    let d = base.join("mentorust");
    let _ = std::fs::create_dir_all(&d);
    Some(d.join("mentorust.stop"))
}

/// 兼容镜像：老版本把标记写在 exe 同目录。
///
/// 写标记时两处都写（保证旧版本/旧路径也看得到），
/// 读标记时两处任一存在即算「已手动断开」（保证旧标记也仍然生效）。
fn stop_flag_legacy_path() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("mentorust.stop")))
}

/// 供 GUI 模块查询：用户是否已手动断开。
pub(crate) fn manual_disconnect_latched() -> bool {
    stop_flag_set()
}

fn stop_flag_set() -> bool {
    let fixed = stop_flag_path().map(|p| p.exists()).unwrap_or(false);
    let legacy = stop_flag_legacy_path().map(|p| p.exists()).unwrap_or(false);
    fixed || legacy
}

fn set_stop_flag(on: bool) {
    if let Some(p) = stop_flag_path() {
        if on {
            let _ = std::fs::write(&p, "manual disconnect\n");
        } else {
            let _ = std::fs::remove_file(&p);
        }
    }
    // 兼容镜像：老版本/旧路径也写一份。
    if let Some(p) = stop_flag_legacy_path() {
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
/// 日志文件路径（轮转时要用）与累计行数（每 100 行触发一次体积检查）。
static LOG_PATH: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);
static LOG_LINES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// 进程角色：`gui` / `ghost` / `cli`。
/// 长期测试时 GUI 日志和后台认证进程日志必须能分开 —— 掉线判定发生在
/// ghost 里，但用户点「连接」的动作发生在 gui 里。
static LOG_ROLE: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

struct SimpleLogger;

/// 本地时间 YYYY-MM-DD HH:MM:SS（本机固定 UTC+8，中国大陆无夏令时，无需时区库）
///
/// 以前只打 HH:MM:SS：日志会连续累积很多天，事后无法判断某条记录
/// 属于哪一天，跨天分析只能靠猜测（2026-10-20 分析时整体偏了 7 天）。
fn now_stamp() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let local = dur.as_secs() + 8 * 3600;
    let (y, mo, d) = civil_from_days((local / 86_400) as i64);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        y, mo, d,
        (local / 3600) % 24,
        (local / 60) % 60,
        local % 60,
        dur.subsec_millis()
    )
}

/// 日志目录：统一到 %LOCALAPPDATA%\mentorust\logs\。
///
/// 之前日志写在 **exe 同目录**，而机器上有三份 exe（工程根 / portable/ /
/// target\release\），于是三份 exe 写三个目录、互不相认 —— 长期测试时
/// 根本说不清"哪份日志才是那一次连接"的。统一到一个固定目录才对得上。
fn log_dir() -> Option<std::path::PathBuf> {
    let base = std::env::var("LOCALAPPDATA")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var("APPDATA").ok().map(std::path::PathBuf::from))?;
    let d = base.join("mentorust").join("logs");
    let _ = std::fs::create_dir_all(&d);
    Some(d)
}

/// 当天日志文件名：mentorust-2026-10-21-ghost.log
///
/// 按天分文件 —— 30 天挂机测试不会把最早的证据轮转掉。
fn log_file_for(role: &str) -> Option<std::path::PathBuf> {
    let d = log_dir()?;
    let stamp = now_stamp();
    let day = &stamp[..10];
    Some(d.join(format!("mentorust-{}-{}.log", day, role)))
}

/// 由「1970-01-01 起的整日数」反算年月日（Howard Hinnant civil_from_days 算法）。
/// 纯整数运算，不引入 chrono，避免为一个时间戳多背一个依赖。
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((if m <= 2 { y + 1 } else { y }) as i32, m, d)
}

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let role = LOG_ROLE
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| String::from("?"));
        let line = format!(
            "{} [{:<6}] {:<5} {}\n",
            now_stamp(),
            role,
            record.level(),
            record.args()
        );
        if let Ok(mut guard) = LOG_FILE.lock() {
            if let Some(f) = guard.as_mut() {
                let _ = f.write_all(line.as_bytes());
                let _ = f.flush();
            }
        }
        // 每 100 行查一次体积：只在 init 时查的话，进程连跑几天
        // （掉线重试循环能刷出上千行/天）会把更早的证据直接冲掉。
        if LOG_LINES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 100 == 0 {
            maybe_rotate_log();
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
    // 角色先定下来：--ghost 是后台认证进程，其余是 GUI / CLI。
    let role = if std::env::args().any(|a| a == "--ghost") {
        "ghost"
    } else if std::env::args().any(|a| a == "--startup") {
        "startup"
    } else if std::env::args().any(|a| a == "logoff") {
        "logoff"
    } else {
        "gui"
    };
    if let Ok(mut g) = LOG_ROLE.lock() {
        *g = String::from(role);
    }

    // 主日志：%LOCALAPPDATA%\mentorust\logs\mentorust-YYYY-MM-DD-<role>.log
    let path = log_file_for(role);
    if let Some(p) = path.clone() {
        if let Ok(mut g) = LOG_PATH.lock() {
            *g = Some(p.clone());
        }
        if let Ok(f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
        {
            if let Ok(mut g) = LOG_FILE.lock() {
                *g = Some(f);
            }
        }
        // 兼容：exe 同目录也留一份，老习惯看那儿的同学不会找不到。
        // 但真正的分析入口是 logs\ 目录。
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let legacy = dir.join("mentorust.log");
                if legacy != p {
                    // 只在 legacy 不存在时创建，避免与主文件混写
                    if !legacy.exists() {
                        let _ = std::fs::write(&legacy, b"");
                    }
                }
            }
        }
    }
    let _ = log::set_logger(&SimpleLogger);
    log::set_max_level(log::LevelFilter::Info);
    info!(
        "[BOOT] role={} pid={} log={:?}",
        role,
        std::process::id(),
        path.as_ref().map(|p| p.display().to_string())
    );
}

/// 日志超过 2 MB 就滚动：mentorust.log -> .log.1 -> .log.2（保留两份）。
/// Windows 上必须先放掉文件句柄才能改名，所以这里显式置 None 再重开。
fn maybe_rotate_log() {
    let path = match LOG_PATH.lock() {
        Ok(g) => g.clone(),
        Err(_) => None,
    };
    let path = match path {
        Some(p) => p,
        None => return,
    };
    // 单文件上限放宽到 32 MB：现在的基线采样每 60 秒一条、加上重连细节，
    // 一天大约几百 KB，32 MB 足够覆盖一整天的极端情况。
    let too_big = std::fs::metadata(&path).map(|m| m.len() > 32_000_000).unwrap_or(false);
    if !too_big {
        // 顺手清理 30 天前的旧日志 —— 长期挂机不能无限涨盘。
        if let Some(dir) = path.parent() {
            if let Ok(rd) = std::fs::read_dir(dir) {
                let cutoff = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    .saturating_sub(30 * 86_400);
                for e in rd.flatten() {
                    let fname = e.file_name().to_string_lossy().to_string();
                    if !fname.starts_with("mentorust-") || !fname.ends_with(".log") {
                        continue;
                    }
                    let mtime = e
                        .metadata()
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(u64::MAX);
                    if mtime < cutoff {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
        }
        return;
    }
    if let Ok(mut g) = LOG_FILE.lock() {
        *g = None;
    }
    // 同一天的文件改名成 .1 / .2（不是跨天），当天日志仍然连续。
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("mentorust")
        .to_string();
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let _ = std::fs::remove_file(dir.join(format!("{}.2.log", stem)));
    let _ = std::fs::rename(dir.join(format!("{}.1.log", stem)), dir.join(format!("{}.2.log", stem)));
    let _ = std::fs::rename(&path, dir.join(format!("{}.1.log", stem)));
    if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        if let Ok(mut g) = LOG_FILE.lock() {
            *g = Some(f);
        }
    }
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

    // —— clap 的查询类参数（--version / --help）与参数错误必须在 init_logging
    //    之前终结：晚一步就会往 GUI 日志写一条多余的 [BOOT]、把 GUI 启动流程
    //    整个走一遍才退出（2026-10-21 实测：跑一次 --version 多起一个进程）。
    //    --ghost / --auto / --startup 是内部路径，参数集不走 clap，先放行。
    let argv: Vec<String> = std::env::args().collect();
    let internal_path = argv
        .iter()
        .any(|a| a == "--ghost" || a == "--auto" || a == "--startup");
    if !internal_path {
        // 成功也继续往下走（后面还会正式 parse 一次）；失败时 clap 自己打印
        // （版本/帮助走 stdout，错误走 stderr）并以对应退出码结束。
        if let Err(e) = EapArgs::try_parse_from(argv.clone()) {
            e.exit();
        }
    }

    init_logging();
    // release 编成 panic=abort：未捕获的 panic 会让进程无声消失，
    // 日志里一个字都不留，事后完全无法区分「崩了」还是「被杀了」。
    std::panic::set_hook(Box::new(|info| {
        error!("[PANIC] 认证进程异常终止: {}", info);
    }));

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
        // 凭据可由 GUI 通过**匿名管道**（本进程 stdin）传入，不落命令行 ——
        // 命令行参数在同用户权限下任何进程都能读到（Win32_Process.CommandLine）。
        let (mut cred_user, mut cred_pass) = (None, None);
        if argv.iter().any(|a| a == "--cred-stdin") {
            #[cfg(target_os = "windows")]
            if let Some((u, p)) = read_cred_stdin() {
                cred_user = Some(u);
                cred_pass = Some(p);
            }
        }
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
        let user = cred_user
            .or_else(|| opt("--gui-user").filter(|s| !s.is_empty()))
            .or_else(|| saved_cred("user"))
            .unwrap_or_else(|| DEFAULT_USER.to_string());
        // 不再接受 `--gui-pass`：明文口令一旦进命令行，同用户下任何进程
        // 枚举 CommandLine 就能读到。只认管道（--cred-stdin）与 ini 密文。
        let pass = cred_pass
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
        Some(EapCommands::DhcpTest { nic, release }) => {
            dhcp_test(&nic, release);
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

/// 按 MAC 找 10.x 地址 —— 网卡 GUID 变化后的兜底。
///
/// 见 `net::get_network_interface_by_mac` 的说明：名字会变，MAC 不会。
fn campus_ipv4_by_mac(mac: &[u8; 6]) -> Option<std::net::Ipv4Addr> {
    let iface = net::get_network_interface_by_mac(mac)?;
    iface.ips.iter().find_map(|ip| match ip.ip() {
        IpAddr::V4(v4) if v4.octets()[0] == 10 => Some(v4),
        _ => None,
    })
}

/// 统一取「本机 10.x 地址」：先按名字，名字失效则按 MAC 兜底。
///
/// 名字失效在网卡重新枚举后是常态（实测 GUID 变过），必须兜住，
/// 否则在线判定恒为 false，会把一段完全正常的连接记录成连续掉线。
fn campus_ipv4_resilient(nic_name: &str, mac: &[u8; 6]) -> Option<std::net::Ipv4Addr> {
    if let Some(ip) = campus_ipv4_of(nic_name) {
        return Some(ip);
    }
    if let Some(ip) = campus_ipv4_by_mac(mac) {
        return Some(ip);
    }
    None
}

/// 认证网卡是否真的能上网：必须用它自己的源地址做 DNS 探测。
///
/// 用「任意 10.x 网卡」判断在线是错的：同时连着校园 Wi-Fi 时，
/// Wi-Fi 会替有线"回答"探测，导致掉线被误判为在线。
/// 掉线模拟：还剩几次探测要报「不通」。
///
/// 仅由 `MENTORUST_SIMULATE_DROP` 设置，用完即清零。
/// 目的是在**不动网络**的前提下驱动掉线判定的完整代码路径
/// （offline_strikes -> OFFLINE_STRIKES -> [EVT:DROP] -> 重认证）。
/// 真实断网需要管理员（改路由/禁用网卡），而且会连带切断
/// 自动化代理自己的网络，所以走这条受控的模拟路径。
static SIMULATE_DROP_LEFT: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);
/// 环境变量只读一次 —— 否则预算耗尽后会被重新填满，变成无限掉线循环。
static SIMULATE_DROP_INITED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
/// 「掉一次就停」模式：触发第一次 [EVT:DROP] 后自动关闭模拟。
static SIMULATE_DROP_ONCE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// 从环境变量取一次模拟次数（每个进程只取一次，避免每轮循环重读）。
fn simulate_drop_budget() -> u32 {
    use std::sync::atomic::Ordering;
    // 只在第一次调用时读环境变量。v2 在这里每次都读，导致预算耗尽后
    // 被重新填满 -> 无限掉线循环。
    if !SIMULATE_DROP_INITED.swap(true, Ordering::SeqCst) {
        if let Ok(v) = std::env::var("MENTORUST_SIMULATE_DROP") {
            if let Ok(n) = v.trim().parse::<u32>() {
                if n > 0 {
                    SIMULATE_DROP_LEFT.store(n, Ordering::SeqCst);
                    SIMULATE_DROP_ONCE.store(
                        std::env::var("MENTORUST_SIMULATE_DROP_ONCE")
                            .map(|x| x.trim() == "1")
                            .unwrap_or(false),
                        Ordering::SeqCst,
                    );
                    warn!(
                        "[TEST] 掉线模拟已启用：接下来 {} 次探测将报「不通」{}",
                        n,
                        if SIMULATE_DROP_ONCE.load(Ordering::SeqCst) {
                            "（一次性，触发掉线后自动关闭）"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
    }
    SIMULATE_DROP_LEFT.load(Ordering::SeqCst)
}

/// 掉线判定成立后调用：一次性模式下关闭模拟，让会话恢复正常。
fn simulate_drop_disarm() {
    use std::sync::atomic::Ordering;
    if SIMULATE_DROP_ONCE.load(Ordering::SeqCst) {
        SIMULATE_DROP_LEFT.store(0, Ordering::SeqCst);
        warn!("[TEST] 一次性掉线模拟已用完，模拟关闭，后续探测恢复真实结果");
    }
}

fn campus_online(nic_name: &str) -> bool {
    campus_ipv4_of(nic_name)
        .map(|ip| online_check(&ip))
        .unwrap_or(false)
}

/// 掉线模拟的**唯一判定点**。
///
/// 主循环调的是 `campus_online_resilient()`，不是 `campus_online()`，
/// 所以模拟必须挂在这一层，否则永远不会被触发（v1 就踩了这个坑）。
fn simulate_drop_active() -> bool {
    use std::sync::atomic::Ordering;
    let budget = simulate_drop_budget();
    if budget == 0 {
        return false;
    }
    SIMULATE_DROP_LEFT.fetch_sub(1, Ordering::SeqCst);
    true
}

/// 带 MAC 兜底的在线判定（见 `campus_ipv4_resilient`）。
fn campus_online_resilient(nic_name: &str, mac: &[u8; 6]) -> bool {
    // 掉线模拟优先：让主循环的探测报「不通」，驱动
    // offline_strikes -> OFFLINE_STRIKES -> [EVT:DROP] -> 重认证
    // 这条完整路径，而**不动真实网络**。
    if simulate_drop_active() {
        return false;
    }
    campus_ipv4_resilient(nic_name, mac)
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

/// 用 Windows DPAPI 加密口令（**当前用户**作用域），返回十六进制串。
///
/// 只在这台机器的这个 Windows 用户下解得开：ini 被拷走、被别的账户读到，
/// 拿到的也只是一串密文。`CRYPTPROTECT_UI_FORBIDDEN`(0x1) 保证后台
/// 无人值守时绝不弹认证框。
#[cfg(target_os = "windows")]
pub fn pass_encrypt(plain: &str) -> Option<String> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};
    if plain.is_empty() {
        return None;
    }
    let mut data = plain.as_bytes().to_vec();
    let bin = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_mut_ptr(),
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    unsafe {
        if CryptProtectData(
            &bin,
            windows::core::PCWSTR::null(),
            None,
            None,
            None,
            0x1,
            &mut out,
        )
        .is_err()
        {
            return None;
        }
        let buf = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(out.pbData as *mut core::ffi::c_void));
        Some(hex::encode(buf))
    }
}

/// 解开 `pass_encrypt` 写下的密文；换机器 / 换用户 / 密文被篡改都返回 None。
#[cfg(target_os = "windows")]
pub fn pass_decrypt(enc: &str) -> Option<String> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    let mut data = hex::decode(enc.trim()).ok()?;
    if data.is_empty() {
        return None;
    }
    let bin = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_mut_ptr(),
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    unsafe {
        if CryptUnprotectData(&bin, None, None, None, None, 0x1, &mut out).is_err() {
            return None;
        }
        let buf = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(out.pbData as *mut core::ffi::c_void));
        String::from_utf8(buf).ok()
    }
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
    // 口令存的是 DPAPI 密文（`pass_enc=`）；老的明文 `pass=` 仅在迁移期兜底。
    if key == "pass" {
        for line in txt.lines() {
            if let Some(v) = line.strip_prefix("pass_enc=") {
                if let Some(plain) = pass_decrypt(v) {
                    return Some(plain);
                }
            }
        }
    }
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

/// 从 stdin 读两行凭据（`user\npass\n`）——GUI 通过匿名管道传入，**不经过命令行**。
/// 读不到（父进程没写就退出 / 管道已关）返回 None，调用方回落到 ini。
#[cfg(target_os = "windows")]
fn read_cred_stdin() -> Option<(String, String)> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    let mut u = String::new();
    let mut p = String::new();
    if lock.read_line(&mut u).ok()? == 0 {
        return None;
    }
    if lock.read_line(&mut p).ok()? == 0 {
        return None;
    }
    let u = u.trim_end_matches(['\r', '\n']).to_string();
    let p = p.trim_end_matches(['\r', '\n']).to_string();
    if u.is_empty() || p.is_empty() {
        return None;
    }
    Some((u, p))
}

/// 启动后台认证进程，带上网卡。
///
/// **凭据不进命令行**：账号密码通过匿名管道写进子进程的 stdin
/// （子进程带 `--cred-stdin`），命令行里只剩 `--ghost --gui-nic "..."`。
/// 以前是 `--gui-pass "明文"`，同用户权限下任何进程枚举进程命令行
/// 都能直接读到口令。
#[cfg(target_os = "windows")]
fn spawn_ghost_with(user: &str, pass: &str, nic: &str) {
    use windows::Win32::Foundation::{
        CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT,
    };
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{
        CreateFileA, WriteFile, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_SHARE_MODE, OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::STARTF_USESTDHANDLES;

    let current_exe = std::env::current_exe().expect("Failed to get current executable path");

    unsafe {
        // ---- 1) 匿名管道：读端给子进程，写端留给自己且**不可继承** ----
        // 写端若被子进程继承，它自己也持有一份写句柄，父进程关掉后它等不到 EOF。
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: BOOL(1),
        };
        let (mut rd, mut wr) = (HANDLE::default(), HANDLE::default());
        let piped = CreatePipe(&mut rd, &mut wr, Some(&sa), 0).is_ok();
        if piped {
            let _ = SetHandleInformation(wr, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
        }

        // ---- 2) 命令行：只有管道建成功才带 --cred-stdin，否则子进程会死等 stdin ----
        let cmd = if piped {
            format!("\"{}\" --ghost --gui-nic \"{}\" --cred-stdin", current_exe.display(), nic)
        } else {
            format!("\"{}\" --ghost --gui-nic \"{}\"", current_exe.display(), nic)
        };
        let command_line = match CString::new(cmd) {
            Ok(c) => c,
            Err(_) => {
                error!("命令行含 NUL 字节，后台进程未启动");
                return;
            }
        };

        let mut startup_info = STARTUPINFOA::default();
        startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut nul = HANDLE::default();
        if piped {
            // stdout/stderr 指到 NUL：否则子进程继承到无效句柄，写 stderr 会失败
            if let Ok(h) = CreateFileA(
                PCSTR(b"NUL\0".as_ptr()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0),
                None,
                OPEN_EXISTING,
                Default::default(),
                HANDLE(ptr::null_mut()),
            ) {
                nul = h;
            }
            startup_info.dwFlags = STARTF_USESTDHANDLES;
            startup_info.hStdInput = rd;
            startup_info.hStdOutput = nul;
            startup_info.hStdError = nul;
        }

        let mut process_info = PROCESS_INFORMATION::default();
        let success = CreateProcessA(
            PCSTR::null(),
            PSTR(command_line.as_ptr() as *mut _),
            None,
            None,
            BOOL(if piped { 1 } else { 0 }),
            CREATE_NO_WINDOW,
            None,
            PCSTR::null(),
            &startup_info,
            &mut process_info,
        );

        // ---- 3) 写凭据后立刻关掉写端：子进程读到两行就继续 ----
        if piped {
            let mut payload = Vec::with_capacity(user.len() + pass.len() + 2);
            payload.extend_from_slice(user.as_bytes());
            payload.push(b'\n');
            payload.extend_from_slice(pass.as_bytes());
            payload.push(b'\n');
            let mut written = 0u32;
            let _ = WriteFile(wr, Some(&payload), Some(&mut written), None);
            for b in payload.iter_mut() {
                *b = 0; // 尽力把明文从这块堆内存抹掉
            }
            let _ = CloseHandle(wr);
            let _ = CloseHandle(rd);
            if !nul.0.is_null() {
                let _ = CloseHandle(nul);
            }
        }

        if success.is_ok() {
            info!("后台认证进程已启动，PID: {}", process_info.dwProcessId);
            let _ = CloseHandle(process_info.hProcess);
            let _ = CloseHandle(process_info.hThread);
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

/// 诊断：只测 DHCP 续租，不发 EAPOL、不改动当前连接。
///
/// `IpRenewAddress` 只续租已有租约，不会断网；`--release` 才会先释放
/// （那会短暂失去地址，只在确实要验证释放路径时用）。
fn dhcp_test(nic_name: &str, do_release: bool) {
    let devices = match Device::list() {
        Ok(d) => d,
        Err(e) => {
            error!("枚举网卡失败: {:?}", e);
            return;
        }
    };

    // 留空则自动挑一张带 10.x 的卡 —— 正常使用中就是校园网有线口。
    let dev = if nic_name.is_empty() {
        devices
            .iter()
            .find(|d| {
                d.addresses.iter().any(|a| match a.addr {
                    std::net::IpAddr::V4(v) => v.octets()[0] == 10,
                    _ => false,
                })
            })
            .or_else(|| devices.first())
            .cloned()
    } else {
        devices.iter().find(|d| d.name == nic_name).cloned()
    };

    let Some(dev) = dev else {
        error!("未找到网卡");
        return;
    };
    let Some(inet) = net::get_network_interface_by_name(&dev.name) else {
        error!("未找到网卡的MAC地址: {}", dev.name);
        return;
    };
    let mac = inet.mac.unwrap().to_string().to_lowercase();
    let mut local_mac = [0u8; 6];
    if hex::decode_to_slice(mac.replace(":", ""), &mut local_mac).is_err() {
        error!("MAC 解析失败: {}", mac);
        return;
    }

    info!("[DHCP-TEST] 网卡: {}", dev.desc.clone().unwrap_or(dev.name.clone()));
    info!("[DHCP-TEST] MAC : {}", mac);

    // 当前地址，方便对照
    let before = dhcp::wait_dhcp_ready(&dev.name, Duration::from_millis(1));
    info!("[DHCP-TEST] 续租前地址: {:?}", before);

    if do_release {
        warn!("[DHCP-TEST] --release：先释放租约（会短暂失去地址）");
        match dhcp::release_dhcp(&dev.name, Some(&local_mac)) {
            Ok(c) => info!("[DHCP-TEST] IpReleaseAddress -> code={} (成功)", c),
            Err(c) => error!("[DHCP-TEST] IpReleaseAddress -> code=0x{:X} (失败)", c),
        }
    }

    match dhcp::renew_dhcp(&dev.name, Some(&local_mac)) {
        Ok(c) => info!("[DHCP-TEST] IpRenewAddress -> code={} (成功)", c),
        Err(c) => error!("[DHCP-TEST] IpRenewAddress -> code=0x{:X} (失败)", c),
    }

    // 给系统几秒钟走完 DHCP 握手再读地址
    let after = dhcp::wait_dhcp_ready(&dev.name, Duration::from_secs(8));
    info!("[DHCP-TEST] 续租后地址: {:?}", after);
}

/// 释放该网卡的 DHCP 租约（尽力而为，失败只记日志）。
///
/// 官方客户端的做法是 `IpReleaseAddress()`（`dhcp::release_dhcp`）。
/// 用户态程序多半调不动（需要管理员），此时退回 `ipconfig /release`
/// —— 官方也用同一套机制（`FUN_14018BC90` 走 `\ipconfig.exe /renew`，
/// release 是对应的另一半）。
///
/// ⚠️ 这里**不 spawn 任何控制台子进程**：GUI 子系统下任何控制台子进程
/// 都会让 Windows 弹一个黑色窗口。`ipconfig` 是控制台程序，不能直接跑。
/// 因此只走 API，失败就如实记录，不做 GUI 里会弹黑框的事。
fn release_lease(nic_name: &str, mac: &[u8; 6]) {
    match dhcp::release_dhcp(nic_name, Some(mac)) {
        Ok(code) => {
            info!("[LOGOFF] DHCP 租约已释放 (code={})，网卡不再持有校园网地址", code);
        }
        Err(code) => {
            // 0x57 = ERROR_INVALID_PARAMETER（多半是缺管理员权限）
            // 0xC351 = 取网卡信息失败；0xC353 = 接口表里找不到该网卡
            warn!(
                "[LOGOFF] 释放 DHCP 租约失败 (code=0x{:X})：网卡地址可能仍保留（用户态通常缺少权限）",
                code
            );
        }
    }
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

    // 先把名字取出来：下面 `Capture::from_device(dev)` 会把 dev 移走，
    // 之后就没法再引用它了（release_lease 需要网卡名）。
    let dev_name = dev.name.clone();

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

    let mut sent = 0u8;
    for dest in [[0x01u8, 0x80, 0xc2, 0x00, 0x00, 0x03], [0x01, 0xd0, 0xf9, 0x00, 0x00, 0x03]] {
        let mut frame = Vec::with_capacity(18);
        frame.extend_from_slice(&dest);
        frame.extend_from_slice(&local_mac);
        frame.extend_from_slice(&0x888e_u16.to_be_bytes());
        frame.push(0x01); // version 802.1X-2001
        frame.push(0x02); // type EAPOL-Logoff
        frame.extend_from_slice(&0x0000_u16.to_be_bytes());
        match cap.sendpacket(frame.as_slice()) {
            Ok(_) => {
                sent += 1;
                info!("已向 {:02x?} 发送 EAPOL-Logoff", dest);
            }
            Err(e) => error!("发送下线包失败: {}", e),
        }
    }

    if sent > 0 {
        info!(
            "[LOGOFF] 下线请求已发送（{}/2 个地址），校园网会话已注销。重新联网请双击 mentorust.exe。",
            sent
        );
    } else {
        // 之前这里无条件说"已发送"，即使两帧都失败 —— 误导。
        warn!(
            "[LOGOFF] 两个地址的 EAPOL-Logoff 都发送失败，服务器侧会话可能仍挂着，稍后需等 BRAS 超时。"
        );
    }

    // 4. 释放 DHCP 租约 —— 与官方一致。
    //
    // 官方 8021x.exe 在认证流程内就做这件事：
    //     FUN_14006D730  "Release IP wired" -> FUN_140184AE0 -> IpReleaseAddress()
    // 不释放的话，机器上仍留着一个 10.x 地址和一份有效租约，
    // 校园网会话却已经没了 —— 这不算"干净"。
    //
    // ⚠️ 这里**不能**写 `drop(cap)`：抓包句柄已经失效（发送失败就是这个
    // 原因），pcap 的 Drop 实现会 panic；而 release 版是 `panic = 'abort'`，
    // panic 会**静默杀死进程** —— 表现为"日志到某一行戛然而止，
    // 后面所有清理都没执行"。句柄在函数返回时自然释放即可。
    release_lease(&dev_name, &local_mac);
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

    let mac = inet.mac.unwrap().to_string().to_lowercase();
    if mac.len() != 17 {
        error!("MAC地址({})格式错误，请检查MAC地址是否正确！", mac);
        return;
    }
    // 原始 MAC 字节：DHCP 接口索引按 MAC 匹配比按网卡名匹配可靠
    // （pnet 给的是注册表 AdapterName，MIB_IF_ROW2.Alias 给的是友好名，三处口径不一致）。
    let mac_bytes: Option<[u8; 6]> = hex::decode(mac.replace(":", "")).ok().and_then(|v| {
        if v.len() == 6 {
            let mut a = [0u8; 6];
            a.copy_from_slice(&v);
            Some(a)
        } else {
            None
        }
    });
    let mac_ref = mac_bytes.as_ref().map(|m| &m[..]);

    // ===== 认证前确保 DHCP 就绪（官方 [DHCPMODE] EnableBeforeAuth=1）=====
    //
    // 官方 8021x.exe 的做法：认证**之前**就启动 DHCP，让 EAPOL 握手发生在一个
    // 已经持有合法租约的状态上；必要时在认证流程内部直接 "Release IP wired"
    // → IpReleaseAddress() → InitDhcp 把地址彻底翻新。
    //
    // 为什么要照做（本项目实测 2026-10-20）：
    //   · 认证时网卡是 APIPA(169.254.x.x) 建立的会话，会被 BRAS 在 3600 s 准点踢掉；
    //   · 建立时已持有 10.x 的会话能活 87~207 分钟；
    //   · 本项目的 EAP 响应帧用网卡 IPv4 作源 IP（见 start_loop），带着 APIPA 去
    //     认证等于发出源地址非法的帧。
    {
        let mut ready = dhcp::wait_dhcp_ready(&nic_name, Duration::from_secs(2));
        if ready.is_none() {
            if dhcp_mode == 3 {
                // dhcp_mode=3 = 认证前 DHCP：对应官方最彻底的做法，
                // 先 IpReleaseAddress 再 IpRenewAddress，让 DHCP 完整重走握手。
                info!("[DHCP] 认证前无 10.x 地址，按 dhcp_mode=3 执行『释放+重续』");
                match dhcp::recycle_dhcp(&nic_name, mac_ref) {
                    Ok(code) => info!("[DHCP] 释放+重续已提交 (code={})", code),
                    Err(code) => warn!("[DHCP] 释放+重续失败 (code=0x{:X})", code),
                }
                ready = dhcp::wait_dhcp_ready(&nic_name, Duration::from_secs(15));
            } else {
                // 默认：官方 EnableBeforeAuth=1 的等价 —— 温和续租一次即可，
                // 不动已有租约，避免打断正在跑的业务流量。
                info!("[DHCP] 认证前无 10.x 地址，触发一次续租（等价官方 InitDhcp）");
                match dhcp::renew_dhcp(&nic_name, mac_ref) {
                    Ok(code) => info!("[DHCP] 续租已提交 (code={})", code),
                    Err(code) => {
                        // 0x57 = ERROR_INVALID_PARAMETER，不是权限问题
                        // （权限问题是 0x5）。2026-10-29 实测：把完整的
                        // IP_ADAPTER_INDEX_MAP（Index + Name）传进去，普通
                        // 用户权限就能调通；传空 Name 才会拿到 0x57。
                        // 所以真出现 0x57 要先查 map 构造，而不是断定"没权限"。
                        warn!(
                            "[DHCP] 续租请求被拒 (code=0x{:X})，降级为纯等待系统 DHCP 客户端",
                            code
                        );
                    }
                }
                ready = dhcp::wait_dhcp_ready(&nic_name, Duration::from_secs(12));
            }
        }
        match ready {
            Some(ip) => info!("[DHCP] 认证前已就绪: {}", ip),
            None => warn!("[DHCP] 认证前仍未取得 10.x 地址（会话可能被限时 60 分钟）"),
        }
    }

    // 测试钩子：只验证「认证前 DHCP」这一段就退出，不发任何 EAPOL。
    // 用于在已认证的机器上安全地验证本段逻辑（真跑认证会因同 MAC 双客户端
    // 被服务器判用户冲突）。
    if std::env::var("MENTORUST_DHCP_PROBE").is_ok() {
        info!("[DHCP] MENTORUST_DHCP_PROBE 生效：只验证认证前 DHCP 阶段，不发起认证");
        return;
    }

    // DHCP 就绪之后再采集地址：EAP 响应帧用这里的 IPv4 作源 IP，
    // 放在 DHCP 之前采集只会拿到 APIPA(169.254.x.x) 或 0.0.0.0。
    let mut ipv4 = [0u8; 4];
    let mut ipv6 = [0u8; 16];
    if let Some(iface) = net::get_network_interface_by_name(&nic.name) {
        for ip in iface.ips {
            match ip.ip() {
                IpAddr::V4(v4) => {
                    ipv4 = v4.octets()
                }
                IpAddr::V6(v6) => {
                    ipv6 = v6.to_bits().to_be_bytes()
                }
            }
        }
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

    // dhcp_mode=3（认证前 DHCP）现在**已经真正实现**：见上面「认证前确保 DHCP 就绪」
    // 那段 —— 它会在认证发起前先 IpReleaseAddress + IpRenewAddress 把租约翻新。
    // 这里不再重复处理，只留一条日志。
    if dhcp_mode == 3 {
        info!("dhcp_mode=3：认证前 DHCP 已启用（释放+重续租约）");
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
    const OFFLINE_STRIKES: u32 = 3;   // 连续 3 次探测不通（约 15s）即判定掉线
    // 从 6 降到 3：实测掉线瞬间探测会在 15s 内全部失败，而「假失败」
    // 只会连续出现 1~2 次（单个 ICMP 丢包），3 次足够区分，恢复快一半。
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
    // 本次会话起点与序号：掉线时能直接报「这一轮活了多久」，
    // 不必再靠外部脚本从日志里反推 60 分钟周期。
    let mut session_start = Instant::now();
    let mut session_no: u64 = 0;
    // 探测统计与 IP 基线（每 60 秒落一条，用来判断掉线前是否已在抖动）。
    let mut probe_ok: u64 = 0;
    let mut probe_fail: u64 = 0;
    let mut last_ip: Option<std::net::Ipv4Addr> = None;
    let mut last_probe_report = Instant::now();
    let mut offline_strikes: u32 = 0;
    let mut last_reopen = Instant::now();
    let mut settle_until = Instant::now() + AUTH_SETTLE;   // 稳定期截止时刻
    // 条件式补认证：只在「会话建立时网卡没有有效地址」的情况下做一次。
    // 依据 2026-10-20 的对照：无租约时建立的会话 3607 s 准点掉数据，
    // 而建立时已持有 10.x 的会话活了 207 分钟。
    let mut rebind_due: Option<Instant> = None;
    let mut rebind_done = false;
    // 官方 CDhcpThread 的等价物：后台 DHCP 续租线程句柄（只启动一次）。
    let mut dhcp_renewer: Option<std::thread::JoinHandle<()>> = None;
    // 上次主动触发 DHCP 续租的时刻，避免每轮都去敲 iphlpapi。
    let mut last_dhcp_kick = Instant::now();

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
                    session_start = Instant::now();
                    session_no += 1;
                    info!("[AUTH] 第 {} 次会话开始", session_no);
                    info!(
                        "[EVT:SESSION_BEGIN] sess={} t={} pid={}",
                        session_no,
                        now_stamp(),
                        std::process::id()
                    );
                    settle_until = Instant::now() + AUTH_SETTLE;

                    // 官方由 CDhcpThread（独立 MFC 线程）持续 IpRenewAddress()。
                    // 这里起一个等价的轻量线程：每 30 分钟续租一次 —— 校园网 DHCP
                    // 租约通常 2 小时、T1(50% 租期)=1 小时，30 分钟稳稳早于 T1，
                    // 且续租报文本身也能维持 BRAS 侧的数据通路。
                    // （30 分钟是按 DHCP 语义推的，官方周期未在反编译里直接暴露。）
                    if dhcp_renewer.is_none() {
                        dhcp_renewer = dhcp::spawn_renewer(
                            nic_name.clone(),
                            mac_bytes,
                            Duration::from_secs(1800),
                        );
                        info!("[DHCP] 已启动后台续租线程（周期 1800 秒）");
                        info!(
                            "[DHCP] 注：主动续租需要管理员权限；若无权限该线程会自行停用，"
                        );
                        info!("     系统 DHCP 客户端仍会在 T1 自动续租，不影响本功能。");
                    }

                    // 记下这次会话「出生」时的地址状态 —— 这是判断要不要补认证的唯一依据
                    let birth_ip = campus_ipv4_of(&nic_name);
                    if rebind_done {
                        info!(
                            "[SESSION] 补认证后的会话，起始地址 {}",
                            birth_ip
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "none".to_string())
                        );
                        info!(
                            "[EVT:SESSION_REBIND] sess={} ip={}",
                            session_no,
                            birth_ip
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "none".to_string())
                        );
                    } else if std::env::var("MENTORUST_FORCE_REBIND").is_ok() {
                        // 测试钩子：强制走一次补认证，用来验证 [REBIND] 路径（不影响正常启动）
                        rebind_due = Some(Instant::now() + Duration::from_secs(5));
                        warn!("[REBIND] 测试钩子 MENTORUST_FORCE_REBIND 生效：5 秒后强制补一次重认证");
                    } else if let Some(ip) = birth_ip {
                        info!("[SESSION] 会话起始地址 {}（已持有租约，按正常策略保活）", ip);
                        info!(
                            "[EVT:SESSION_BIRTH] sess={} ip={} had_lease=1",
                            session_no,
                            ip
                        );
                    } else {
                        rebind_due = Some(Instant::now() + AUTH_SETTLE);
                        warn!(
                            "[SESSION] 会话建立时网卡无 10.x 地址（APIPA/无租约）—— 这类会话易在 60 分钟准点被踢，等 DHCP 就绪后补一次重认证"
                        );
                        info!(
                            "[EVT:SESSION_BIRTH] sess={} ip=none had_lease=0",
                            session_no
                        );
                    }
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
            // 用带 MAC 兜底的判定：网卡 GUID 变化后仍能正确识别在线状态，
            // 否则会陷入「每 30 秒误报一次掉线」的假阳性循环。
            // 稳定期（认证后 AUTH_SETTLE=20s）内探测结果被强制当作「在线」，
            // 此时消耗掉线模拟预算等于白烧 —— 所以稳定期内**不调用探测**，
            // 预算只在真正计入 strike 的探测上消耗。
            let online = if Instant::now() < settle_until {
                true
            } else {
                campus_online_resilient(&nic_name, &local_mac)
            };

            // 心跳与探测**解耦**：心跳是会话保活用的，必须无条件按周期发送。
            // 之前把心跳塞在 online 分支里 -> 一旦探测假失败就再也不发心跳，
            // 会话彻底失去保活，表现为「掉线后永远回不来」。
            if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
                let _ = packet_sender.send(Status::Heartbeat { dest_mac });
                last_heartbeat = Instant::now();
            }

            // 条件式补认证：DHCP 拿到地址后，把「无租约时建立」的会话重绑一次。
            // 走 ProbeStartAuth（Logoff×2 + StartAuth），与掉线重连同一条路径。
            if let Some(due) = rebind_due {
                if Instant::now() >= due {
                    match campus_ipv4_of(&nic_name) {
                        Some(ip) => {
                            rebind_due = None;
                            rebind_done = true;
                            info!(
                                "[REBIND] 已拿到 {}，补一次干净重认证，把会话绑回正常策略",
                                ip
                            );
                            phase_auth = true;
                            last_server = Instant::now();
                            retry_at = Instant::now();
                            offline_strikes = 0;
                            let _ = packet_sender.send(Status::ProbeStartAuth { dest_mac });
                            continue;
                        }
                        None => {
                            // 官方 8021x.exe 不是干等 DHCP —— 它会主动
                            // IpRenewAddress() 触发续租（CDhcpThread::RenewDhcpAddr，
                            // FUN_1400A95C0）。这里每 10 秒敲一次，最多等 2 分钟。
                            if Instant::now() >= due + Duration::from_secs(120) {
                                warn!("[REBIND] 等不到 DHCP 地址，放弃补认证（会话按原样保活）");
                                rebind_due = None;
                            } else if last_dhcp_kick.elapsed() >= Duration::from_secs(10) {
                                last_dhcp_kick = Instant::now();
                                match dhcp::renew_dhcp(&nic_name, mac_ref) {
                                    Ok(code) => info!(
                                        "[REBIND] 已触发 DHCP 续租 (code={})，等待地址下发",
                                        code
                                    ),
                                    Err(code) => {
                                        warn!("[REBIND] DHCP 续租失败 (code=0x{:X})", code)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if online {
                probe_ok += 1;
                if offline_strikes > 0 {
                    info!("校园网已恢复在线。");
                    warn!(
                        "[EVT:RECOVERED] sess={} down_s={:.1} ip={}",
                        session_no,
                        session_start.elapsed().as_secs_f64(),
                        campus_ipv4_of(&nic_name)
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "none".to_string())
                    );
                    offline_strikes = 0;
                }
            } else {
                probe_fail += 1;
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
                    let ip = campus_ipv4_of(&nic_name)
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "none".to_string());
                    warn!(
                        "[DROP] 确认已掉线：本次会话持续 {:.1} 分，距上次心跳 {:.1}s，IP={}（重新认证）...",
                        session_start.elapsed().as_secs_f64() / 60.0,
                        last_heartbeat.elapsed().as_secs_f64(),
                        ip
                    );
                    // 机器可解析的掉线事件：会话号 + 精确在线时长 + 心跳间隔。
                    // 3600s 准点掉线的判定完全依赖 up_s 这一项。
                    // 一次性模式：掉线判定成立即关闭模拟。
                    simulate_drop_disarm();
                    warn!(
                        "[EVT:DROP] sess={} up_s={:.1} since_hb_s={:.1} ip={} strikes={}",
                        session_no,
                        session_start.elapsed().as_secs_f64(),
                        last_heartbeat.elapsed().as_secs_f64(),
                        ip,
                        offline_strikes
                    );
                    phase_auth = true;
                    last_server = Instant::now();
                    retry_at = Instant::now();
                    offline_strikes = 0;
                    let _ = packet_sender.send(Status::ProbeStartAuth { dest_mac });
                }
            }
        }

        // 每 60 秒留一条基线。诊断时最需要的三个问题：
        //   掉线前探测是否已经在抖？IP 是否变过？心跳是否还在按周期走？
        // 只有周期性样本才能回答，光有「出错时才写」的日志答不出来。
        if last_probe_report.elapsed() >= Duration::from_secs(60) {
            let ip = campus_ipv4_resilient(&nic_name, &local_mac);
            match (last_ip, ip) {
                (Some(old), Some(new)) if old != new => {
                    warn!("[NET] 本机 10.x 地址变化: {} -> {}", old, new);
                }
                (Some(old), None) => {
                    warn!("[NET] 本机 10.x 地址消失（原 {}）", old);
                }
                (None, Some(new)) => {
                    info!("[NET] 本机 10.x 地址: {}", new);
                }
                _ => {}
            }
            last_ip = ip;
            info!(
                "[PROBE] 近 60s 探测 ok={} fail={}，IP={}，会话 {:.1} 分，距心跳 {:.1}s",
                probe_ok,
                probe_fail,
                ip.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string()),
                session_start.elapsed().as_secs_f64() / 60.0,
                last_heartbeat.elapsed().as_secs_f64()
            );
            probe_ok = 0;
            probe_fail = 0;
            last_probe_report = Instant::now();
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
        // 心跳采样计数：每帧都写会刷出 4000+ 行/天，只记首帧与每 5 帧，
        // 但「序号 + 间隔」都保留 —— 这恰好是判断保活是否失效的两个量。
        let mut beat_n: u64 = 0;
        let mut beat_at = Instant::now();
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
                    beat_n += 1;
                    let gap = beat_at.elapsed().as_secs_f64();
                    beat_at = Instant::now();
                    let seq = echo.as_ref().map(|e| e.no()).unwrap_or(0);
                    let key = echo.as_ref().map(|e| e.key()).unwrap_or(0);
                    let packet = packets::build_heartbeat_packet(&dest_mac, &local_mac, echo.as_mut());
                    send(packet.as_slice());
                    if beat_n == 1 || beat_n % 5 == 0 {
                        info!(
                            "[BEAT] 心跳 #{} seq=0x{:04X} key=0x{:08X} 距上帧 {:.2}s len={}",
                            beat_n, seq, key, gap, packet.len()
                        );
                    }
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
