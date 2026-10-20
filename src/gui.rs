//! 简易图形界面：账号 / 密码输入框 + 「连接」/「断开」按钮。
//!
//! 直接用 Win32 API 实现（windows crate 已在依赖中），不引入任何第三方 GUI 库，
//! 保证最终仍然只有一个 exe。界面只负责"发指令"，真正的认证与心跳由 `--ghost`
//! 后台进程承担 —— 所以关掉窗口也不会掉线。

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::{
    BOOL, COLORREF, ERROR_SUCCESS, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM,
};
use windows::Win32::Graphics::Gdi::{CreateSolidBrush, GetStockObject, DEFAULT_GUI_FONT};
use windows::Win32::System::Console::FreeConsole;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
// 开机自启动走 HKCU\...\Run。注意：**不要**用 schtasks / reg.exe —— 那是子进程，
// 会打破「GUI 进程不派生任何控制台程序（不弹黑窗）」这条硬约束。
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::PCWSTR;

// ===== 控件 ID =====
const ID_USER: i32 = 1001;
const ID_PASS: i32 = 1002;
const ID_BTN_CONNECT: i32 = 1003;
const ID_BTN_DISCONNECT: i32 = 1004;
/// 唯一的「关键信息」行：当前状态 + 最新一条消息，一行依次展示
const ID_INFO: i32 = 1005;
/// 网卡选择下拉框
const ID_NIC: i32 = 1006;
/// 「开机自启动」复选框
const ID_AUTOSTART: i32 = 1007;
/// 「自动连接」复选框（仅当自启动启用时才可勾选）
const ID_AUTOCONNECT: i32 = 1008;

/// 自定义消息：让工作线程把界面更新投递回 UI 线程执行
const WM_APP_PUMP: u32 = WM_APP + 1;

const CLASS_NAME: &str = "MentorustGuiWndClass";
const WIN_TITLE: &str = "校园网认证 · Mentorust";

// ===== 紧凑布局（客户区像素） =====
const CLIENT_W: i32 = 360; // 客户区宽
const CLIENT_H: i32 = 186; // 客户区高：三行输入 + 一排按钮 + 一行选项 + 一行信息
const M: i32 = 14; // 左右边距
const CW: i32 = 294; // 输入框宽度

// ===== 控件样式 =====
// 注意：ES_*/BS_* 是普通 i32 常量，WS_* 是 WINDOW_STYLE 新类型，需要分别处理。
const ST_EDIT: WINDOW_STYLE =
    WINDOW_STYLE(((ES_LEFT | ES_AUTOHSCROLL) as u32) | WS_BORDER.0 | WS_TABSTOP.0);
const ST_EDIT_PASS: WINDOW_STYLE =
    WINDOW_STYLE(((ES_LEFT | ES_AUTOHSCROLL | ES_PASSWORD) as u32) | WS_BORDER.0 | WS_TABSTOP.0);
/// 只读单行信息栏（状态 + 最新消息）
const ST_INFO: WINDOW_STYLE = WINDOW_STYLE((ES_LEFT | ES_AUTOHSCROLL | ES_READONLY) as u32);
/// 网卡下拉框：只能从列表里选（不接受手输），内容多时可滚动
const ST_COMBO: WINDOW_STYLE =
    WINDOW_STYLE((CBS_DROPDOWNLIST as u32) | WS_VSCROLL.0 | WS_TABSTOP.0);
const ST_BTN_DEF: WINDOW_STYLE = WINDOW_STYLE((BS_DEFPUSHBUTTON as u32) | WS_TABSTOP.0);
const ST_BTN: WINDOW_STYLE = WINDOW_STYLE((BS_PUSHBUTTON as u32) | WS_TABSTOP.0);
/// 复选框：点一下由 Windows 自动切换勾选态（BS_AUTOCHECKBOX），不必手写切换逻辑
const ST_CHK: WINDOW_STYLE = WINDOW_STYLE((BS_AUTOCHECKBOX as u32) | WS_TABSTOP.0);

/// BM_GETCHECK / BM_SETCHECK 用的勾选态（对应 BST_UNCHECKED / BST_CHECKED）
const BST_OFF: usize = 0;
const BST_ON: usize = 1;

// ===== 全局状态 =====
enum UiMsg {
    Log(String),
    Status(String),
    Busy(bool),
}

static QUEUE: Mutex<Vec<UiMsg>> = Mutex::new(Vec::new());
/// 当前状态（`● 已连接` / `○ 未连接` / …）与最新一条消息，合并成一行显示
static STATE: Mutex<String> = Mutex::new(String::new());
static LAST_MSG: Mutex<String> = Mutex::new(String::new());
static MAIN_HWND: AtomicIsize = AtomicIsize::new(0);
static BUSY: AtomicBool = AtomicBool::new(false);
/// 下拉框里的网卡项：(NPF 名称, 显示标签)，索引与下拉框一一对应
static NIC_ITEMS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
/// 当前选中的认证网卡（NPF 名称；为空则回退到内置默认）
static NIC_SEL: Mutex<String> = Mutex::new(String::new());
/// 「自动连接」是否勾选（界面 / 配置文件 / 启动逻辑共用这**一份**真相，避免状态漂移）
static AUTO_CONNECT: Mutex<bool> = Mutex::new(false);
/// 本次是否由「开机自启动」拉起 —— 只有这种启动才允许自动发起连接，
/// 手动双击 exe 时即便勾了「自动连接」也只开界面（不擅自联网）。
static STARTUP_LAUNCH: AtomicBool = AtomicBool::new(false);

// ===== 托盘运行态 =====
/// 当前是否真的能上网（决定托盘图标颜色 / 提示文字）
static ONLINE: AtomicBool = AtomicBool::new(false);
/// 托盘图标是否已经挂上
static TRAY_ADDED: AtomicBool = AtomicBool::new(false);
/// 托盘当前展示的在线状态，用来「变了才刷新」，避免每 3 秒空转一次 shell 调用
static TRAY_SHOWN_ONLINE: AtomicBool = AtomicBool::new(false);
/// 两个图标的 HICON（首次用时创建，之后复用；0 = 还没建）
static ICON_ON: AtomicIsize = AtomicIsize::new(0);
static ICON_OFF: AtomicIsize = AtomicIsize::new(0);
/// 是否正在退出 —— 置位后点 X 不再拦截
static EXITING: AtomicBool = AtomicBool::new(false);
/// 「已最小化到托盘」的提示只弹一次，不然每次关窗都打扰
static TRAY_HINTED: AtomicBool = AtomicBool::new(false);

/// `main` 识别到 `--startup` 时调用：标记本次为开机自启动拉起。
pub fn set_startup_launch(on: bool) {
    STARTUP_LAUNCH.store(on, Ordering::SeqCst);
}

/// 当前「自动连接」勾选态
fn auto_connect_now() -> bool {
    *AUTO_CONNECT.lock().unwrap()
}

// ===== 小工具 =====

/// Rust 字符串 → 以 NUL 结尾的 UTF-16（必须绑定到变量，避免临时值提前释放）
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn post(msg: UiMsg) {
    QUEUE.lock().unwrap().push(msg);
    let h = MAIN_HWND.load(Ordering::SeqCst);
    if h != 0 {
        unsafe {
            let _ = PostMessageW(HWND(h as *mut c_void), WM_APP_PUMP, WPARAM(0), LPARAM(0));
        }
    }
}

fn say_log(s: impl Into<String>) {
    post(UiMsg::Log(s.into()));
}

fn say_status(s: impl Into<String>) {
    post(UiMsg::Status(s.into()));
}

// ===== 配置文件（账号密码持久化，放在 exe 同目录） =====

fn config_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.join("mentorust-gui.ini"))
}

/// 界面配置（存在 exe 同目录的 `mentorust-gui.ini`）
struct Cfg {
    user: String,
    pass: String,
    nic: String,
    /// 勾过「自动连接」（最终是否生效还要看开机自启动是否启用）
    autoconnect: bool,
}

fn load_config() -> Cfg {
    if let Some(p) = config_path() {
        if let Ok(txt) = std::fs::read_to_string(&p) {
            let mut c = Cfg {
                user: String::new(),
                pass: String::new(),
                nic: String::new(),
                autoconnect: false,
            };
            let mut legacy_plain = false;
            for line in txt.lines() {
                if let Some(v) = line.strip_prefix("user=") {
                    c.user = v.trim().to_string();
                } else if let Some(v) = line.strip_prefix("pass_enc=") {
                    if let Some(p) = crate::pass_decrypt(v) {
                        c.pass = p;
                    }
                } else if let Some(v) = line.strip_prefix("pass=") {
                    c.pass = v.trim().to_string();
                    legacy_plain = !c.pass.is_empty();
                } else if let Some(v) = line.strip_prefix("nic=") {
                    c.nic = v.trim().to_string();
                } else if let Some(v) = line.strip_prefix("autoconnect=") {
                    c.autoconnect = v.trim() == "1";
                }
            }
            if legacy_plain {
                // 明文口令已落过盘 —— 立刻换成密文，不等用户下次点「连接」
                save_config(&c.user, &c.pass, &c.nic, c.autoconnect);
                log::info!("[SEC] ini 里发现明文口令，已就地改写为 DPAPI 密文");
            }
            if !c.user.is_empty() {
                return c;
            }
        }
    }
    Cfg {
        user: crate::DEFAULT_USER.to_string(),
        pass: crate::DEFAULT_PASS.to_string(),
        nic: String::new(),
        autoconnect: false,
    }
}

fn save_config(user: &str, pass: &str, nic: &str, autoconnect: bool) {
    if let Some(p) = config_path() {
        // 口令只落 DPAPI 密文：ini 拷到别的机器 / 别的账户都解不开
        if let Some(enc) = crate::pass_encrypt(pass) {
            let _ = std::fs::write(
                p,
                format!(
                    "user={}\npass_enc={}\nnic={}\nautoconnect={}\n",
                    user,
                    enc,
                    nic,
                    if autoconnect { 1 } else { 0 }
                ),
            );
        } else {
            let _ = std::fs::write(
                p,
                format!(
                    "user={}\nnic={}\nautoconnect={}\n",
                    user,
                    nic,
                    if autoconnect { 1 } else { 0 }
                ),
            );
        }
    }
}

// ===== 开机自启动（HKCU\...\Run） =====

/// 启动项所在的注册表路径与值名
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "Mentorust";

/// 开机自启动现在是否已启用（只认注册表 —— 单一真相源）
fn autostart_on() -> bool {
    unsafe {
        let sub = wide(RUN_KEY);
        let mut hkey = HKEY(ptr::null_mut());
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(sub.as_ptr()),
            0,
            KEY_QUERY_VALUE,
            &mut hkey,
        )
        .0 != ERROR_SUCCESS.0
        {
            return false;
        }
        let name = wide(RUN_VALUE);
        let rc = RegQueryValueExW(hkey, PCWSTR(name.as_ptr()), None, None, None, None);
        let _ = RegCloseKey(hkey);
        rc.0 == ERROR_SUCCESS.0
    }
}

/// 启用 / 关闭开机自启动（false 时删除该项）。返回是否成功。
fn set_autostart(on: bool) -> bool {
    unsafe {
        let sub = wide(RUN_KEY);
        if !on {
            let mut hkey = HKEY(ptr::null_mut());
            if RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(sub.as_ptr()),
                0,
                KEY_SET_VALUE,
                &mut hkey,
            )
            .0 == ERROR_SUCCESS.0
            {
                let name = wide(RUN_VALUE);
                let _ = RegDeleteValueW(hkey, PCWSTR(name.as_ptr()));
                let _ = RegCloseKey(hkey);
            }
            return true;
        }
        let mut hkey = HKEY(ptr::null_mut());
        if RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(sub.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut hkey,
            None,
        )
        .0 != ERROR_SUCCESS.0
        {
            return false;
        }
        // 开机拉起：打开界面（带 --startup，界面据此决定要不要自动连）
        let exe = std::env::current_exe().unwrap_or_default();
        let cmd = format!("\"{}\" --startup", exe.display());
        let mut data: Vec<u8> = Vec::new();
        for u in cmd.encode_utf16().chain(std::iter::once(0)) {
            data.extend_from_slice(&u.to_le_bytes());
        }
        let name = wide(RUN_VALUE);
        let rc = RegSetValueExW(hkey, PCWSTR(name.as_ptr()), 0, REG_SZ, Some(&data));
        let _ = RegCloseKey(hkey);
        rc.0 == ERROR_SUCCESS.0
    }
}

// ===== 控件操作（只能在 UI 线程调用） =====

unsafe fn set_text(parent: HWND, id: i32, s: &str) {
    if let Ok(c) = GetDlgItem(parent, id) {
        let w = wide(s);
        let _ = SetWindowTextW(c, PCWSTR(w.as_ptr()));
    }
}

unsafe fn get_text(parent: HWND, id: i32) -> String {
    let Ok(c) = GetDlgItem(parent, id) else {
        return String::new();
    };
    let mut buf = vec![0u16; 512];
    let n = GetWindowTextW(c, &mut buf);
    if n <= 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..n as usize])
}

/// 启用 / 禁用控件。
///
/// ⚠️ 必须用 `EnableWindow`，**不能**只发 `WM_ENABLE`：WM_ENABLE 只是给控件
/// 发个"启用状态变了"的通知，并不会设置 WS_DISABLED —— 控件看着照旧、点着也照旧响应。
/// （实测踩过：用 SendMessage(WM_ENABLE) 之后 IsWindowEnabled 仍是 TRUE，
///   于是「自动连接」根本没有置灰。同理，原来 set_busy 想禁用按钮其实也没生效。）
unsafe fn enable(hwnd: HWND, on: bool) {
    let _ = EnableWindow(hwnd, BOOL(if on { 1 } else { 0 }));
}

/// 读复选框勾选态
unsafe fn checkbox_checked(parent: HWND, id: i32) -> bool {
    match GetDlgItem(parent, id) {
        Ok(c) => SendMessageW(c, BM_GETCHECK, WPARAM(0), LPARAM(0)).0 as usize == BST_ON,
        Err(_) => false,
    }
}

/// 按「自启动」状态刷新两个复选框。
/// 关键规则：自启动没开 → 「自动连接」置灰（不可选）并取消勾选 ——
/// 一个不生效的选项不该保持勾着，否则用户会以为它在起作用。
unsafe fn apply_options(parent: HWND, autostart: bool, autocxn: bool) {
    let live = autostart && autocxn;
    if let Ok(c) = GetDlgItem(parent, ID_AUTOSTART) {
        SendMessageW(
            c,
            BM_SETCHECK,
            WPARAM(if autostart { BST_ON } else { BST_OFF }),
            LPARAM(0),
        );
    }
    if let Ok(c) = GetDlgItem(parent, ID_AUTOCONNECT) {
        SendMessageW(
            c,
            BM_SETCHECK,
            WPARAM(if live { BST_ON } else { BST_OFF }),
            LPARAM(0),
        );
        enable(c, autostart);
    }
    *AUTO_CONNECT.lock().unwrap() = live;
}

unsafe fn set_busy(parent: HWND, busy: bool) {
    if let Ok(b) = GetDlgItem(parent, ID_BTN_CONNECT) {
        enable(b, !busy);
    }
    if let Ok(b) = GetDlgItem(parent, ID_BTN_DISCONNECT) {
        enable(b, !busy);
    }
}

/// 把队列里的界面更新在 UI 线程上应用
unsafe fn pump(parent: HWND) {
    let items: Vec<UiMsg> = {
        let mut q = QUEUE.lock().unwrap();
        std::mem::take(&mut *q)
    };
    for it in items {
        match it {
            UiMsg::Status(s) => {
                *STATE.lock().unwrap() = s;
            }
            UiMsg::Busy(b) => {
                let _ = b;
                set_busy(parent, b);
            }
            UiMsg::Log(s) => {
                // 只保留最新一条：一行依次展示，不堆积历史
                *LAST_MSG.lock().unwrap() = s;
            }
        }
    }
    refresh_info(parent);
    // 托盘图标 / 提示文字跟着在线状态走（隐藏到托盘后也在更新）
    sync_tray(parent);
}

/// 把「状态 · 最新消息」拼成一行写进信息栏
unsafe fn refresh_info(parent: HWND) {
    let state = STATE.lock().unwrap().clone();
    let last = LAST_MSG.lock().unwrap().clone();
    let line = match (state.is_empty(), last.is_empty()) {
        (true, true) => String::new(),
        (true, false) => last,
        (false, true) => state,
        (false, false) => format!("{}   {}", state, last),
    };
    set_text(parent, ID_INFO, &line);
}

// ===== 网卡选择 =====

/// 当前认证网卡：用户在下拉框里选过就用它，否则用内置默认。
fn current_nic() -> String {
    let s = NIC_SEL.lock().unwrap().clone();
    if !s.is_empty() {
        return s;
    }
    // 没选过 → 自动挑第一张带 10.x 地址的网卡（校园网网段）；
    // 挑不到才回落到内置默认（发布版为空，由上层提示用户手动选）。
    if let Ok(devs) = pcap::Device::list() {
        if let Some(d) = devs.iter().find(|d| {
            d.addresses
                .iter()
                .any(|a| a.addr.is_ipv4() && a.addr.to_string().starts_with("10."))
        }) {
            return d.name.clone();
        }
    }
    crate::DEFAULT_NIC.to_string()
}

/// 把冗长的系统网卡描述压短，好在一行里放下
fn short_desc(d: &str) -> String {
    let s = d
        .replace("Microsoft Wi-Fi Direct Virtual Adapter", "Wi-Fi Direct 虚拟适配器")
        .replace("VMware Virtual Ethernet Adapter for ", "VMware ")
        .replace("Hyper-V Virtual Ethernet Adapter", "Hyper-V 虚拟以太网")
        .replace("Adapter for loopback traffic capture", "回环 Loopback")
        .replace("WAN Miniport", "WAN 微型端口");
    if s.chars().count() > 44 {
        s.chars().take(43).collect::<String>() + "…"
    } else {
        s
    }
}

/// 扫描本机网卡（走 Npcap，名称与 `-n` / `--gui-nic` 参数完全一致）。
/// 返回 (NPF 名称, 显示标签)；带 10.x 地址的（校园网网段）排在前面。
fn scan_nics() -> Vec<(String, String)> {
    let mut rows: Vec<(u8, String, String)> = Vec::new();
    match pcap::Device::list() {
        Ok(devs) => {
            for d in devs {
                let v4 = d.addresses.iter().find_map(|a| match a.addr {
                    std::net::IpAddr::V4(v) => Some(v),
                    _ => None,
                });
                let base = d.desc.clone().unwrap_or_else(|| d.name.clone());
                let (rank, label) = match v4 {
                    Some(ip) if ip.octets()[0] == 10 => {
                        (0u8, format!("{} · {}", short_desc(&base), ip))
                    }
                    Some(ip) => (1u8, format!("{} · {}", short_desc(&base), ip)),
                    None => (2u8, format!("{} · 无地址", short_desc(&base))),
                };
                rows.push((rank, d.name.clone(), label));
            }
        }
        Err(e) => rows.push((9u8, String::new(), format!("(枚举网卡失败: {})", e))),
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.2.cmp(&b.2)));
    rows.into_iter().map(|(_, n, l)| (n, l)).collect()
}

/// 重建下拉框内容。展开时也会调用 → 网线插拔 / 地址变化都能立刻反映。
unsafe fn reload_nics(combo: HWND) {
    let keep = current_nic();
    let items = scan_nics();

    SendMessageW(combo, CB_RESETCONTENT, WPARAM(0), LPARAM(0));
    let mut sel = 0usize;
    {
        let mut store = NIC_ITEMS.lock().unwrap();
        store.clear();
        for (i, (name, label)) in items.iter().enumerate() {
            let w = wide(label);
            SendMessageW(combo, CB_ADDSTRING, WPARAM(0), LPARAM(w.as_ptr() as isize));
            if !name.is_empty() && *name == keep {
                sel = i;
            }
            store.push((name.clone(), label.clone()));
        }
    }
    if !items.is_empty() {
        SendMessageW(combo, CB_SETCURSEL, WPARAM(sel), LPARAM(0));
        let name = items[sel].0.clone();
        if !name.is_empty() {
            *NIC_SEL.lock().unwrap() = name;
        }
    }
}

/// 用户在下拉框里换了网卡：记住选择（下次打开界面自动选中）
unsafe fn on_nic_changed(parent: HWND) {
    let Ok(combo) = GetDlgItem(parent, ID_NIC) else {
        return;
    };
    let idx = SendMessageW(combo, CB_GETCURSEL, WPARAM(0), LPARAM(0)).0;
    if idx < 0 {
        return;
    }
    let picked = NIC_ITEMS.lock().unwrap().get(idx as usize).cloned();
    let Some((name, label)) = picked else {
        return;
    };
    if name.is_empty() {
        return;
    }
    *NIC_SEL.lock().unwrap() = name;
    let (u, p) = (get_text(parent, ID_USER), get_text(parent, ID_PASS));
    save_config(&u, &p, &current_nic(), auto_connect_now());
    say_log(format!("已选网卡：{}（点「连接」生效）", label));
}

// ===== 业务动作（跑在工作线程） =====

fn do_connect(user: &str, pass: &str, nic: &str) -> String {
    // 这是用户**显式**点「连接」→ 清除「手动断开」标记，恢复自动重连能力。
    crate::set_stop_flag(false);

    // 只认「认证网卡自己」的地址：否则同时连着校园 Wi-Fi 时会被误判成
    // 已在线，点「连接」不生效 —— 表现为"必须先点一次「断开」才能「连接」"。
    //
    // 判据用「探测通」**或**「网卡已拿到 10.x 认证地址」二者之一：
    // 只凭探测会在瞬时丢包时假失败，于是把一条本来好好的、正在工作的连接
    // kill 掉重来 —— 那一下才是真正让用户"掉线"的元凶。
    // 判定"是否已在线"：只认**真实可达**（探测通过）。绝不能用"网卡有 10.x 地址"
    // 当依据 —— 掉线后残留的旧地址会让界面永远显示"已在线"，点「连接」什么都不做
    // （用户看到的"点了连接连不了"）。为对抗瞬时丢包，探测重试 3 次，任一成功即算在线。
    let mut already_online = false;
    for _ in 0..3 {
        if crate::campus_online(nic) {
            already_online = true;
            break;
        }
        thread::sleep(Duration::from_millis(600));
    }

    if already_online {
        // 已经在线：只要保证有保活进程在跑即可。
        // 已在跑就不要再拉一个（会被单实例锁挡回，白白浪费时间）。
        if crate::ghost_running() {
            say_log("后台保活已在运行");
        } else {
            say_log("已在线，启动后台保活...");
            crate::spawn_ghost_with(user, pass, nic);
        }
        say_status("● 已连接");
        return "已在线（后台保活中，掉线自动重连）".to_string();
    }

    // ---- 当前不在线 ----
    // 关键：先把可能残留 / 僵死的后台进程清掉。否则新进程会被单实例锁
    // 直接挡回（旧进程还活着但已经失效），表现出来就是
    // "必须先点一次「断开」才能「连接」"。
    if crate::ghost_running() {
        say_log("清理残留进程...");
        crate::kill_ghosts();
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(250));
            if !crate::ghost_running() {
                break;
            }
        }
    }
    say_log(format!("启动认证（{}）...", user));
    crate::spawn_ghost_with(user, pass, nic);

    for i in 1..=15 {
        thread::sleep(Duration::from_secs(2));
        // 以**真实可达**为准，而不是"拿到 10.x 地址"——残留的旧地址会造成误报。
        if crate::campus_online(nic) {
            say_status("● 已连接");
            return format!("认证成功（{} 秒）", i * 2);
        }
        say_status(format!("连接中... {}/15", i));
    }
    say_status("○ 未连接");
    if crate::ghost_running() {
        // 认证握手成功（后台进程在跑），但数据面不通 —— 多半是校园网侧没放行，
        // 不是账号密码或网线的问题，别让用户去瞎折腾配置。
        "认证已通过，但数据不通（校园网侧未放行，可稍后重试或联系网络中心）".to_string()
    } else {
        "认证超时：请检查 网线 / Npcap / 账号密码".to_string()
    }
}

fn do_disconnect(nic: &str) -> String {
    say_status("断开中...");
    crate::logoff(nic);
    for _ in 0..8 {
        thread::sleep(Duration::from_secs(2));
        if !crate::campus_online(nic) {
            say_status("○ 已断开（手动）");
            return "已断开（手动），不会自动重连".to_string();
        }
    }
    say_status("○ 已断开（手动）");
    "已发注销包，处于手动断开状态（不自动重连）".to_string()
}

fn start_connect(parent: HWND) {
    if BUSY.swap(true, Ordering::SeqCst) {
        return;
    }
    let (user, pass) = unsafe { (get_text(parent, ID_USER), get_text(parent, ID_PASS)) };
    let nic = current_nic();
    if nic.is_empty() {
        unsafe { set_busy(parent, false) };
        BUSY.store(false, Ordering::SeqCst);
        say_status("● 未找到网卡");
        say_log("没找到带 10.x 地址的校园网网卡，请在下拉框里手动选择");
        return;
    }
    if user.trim().is_empty() || pass.is_empty() {
        unsafe { set_busy(parent, false) };
        BUSY.store(false, Ordering::SeqCst);
        say_status("● 参数不完整");
        say_log("账号和密码不能为空");
        return;
    }
    save_config(&user, &pass, &nic, auto_connect_now());
    unsafe { set_busy(parent, true) };
    say_status("连接中...");
    say_log("开始连接...");
    thread::spawn(move || {
        let r = do_connect(&user, &pass, &nic);
        say_log(r);
        BUSY.store(false, Ordering::SeqCst);
        post(UiMsg::Busy(false));
    });
}

fn start_disconnect(parent: HWND) {
    if BUSY.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe { set_busy(parent, true) };
    say_log("开始断开...");
    let nic = current_nic();
    thread::spawn(move || {
        let r = do_disconnect(&nic);
        say_log(r);
        BUSY.store(false, Ordering::SeqCst);
        post(UiMsg::Busy(false));
    });
}

// ===== 系统托盘 =====
//
// 交互约定（与常见桌面软件一致）：
//   点 X            → 隐藏到托盘，后台认证 + 心跳继续跑，网络不断
//   双击 / 左键单击 → 打开主界面
//   右键            → 菜单：打开主界面 / 立即连接 / 断开连接 / 退出
//   「退出」        → 注销会话 + 结束后台认证进程 + 关闭本程序（保活一起停）

/// 托盘图标的回调消息（lParam = 鼠标消息，wParam = 图标 ID）
const WM_TRAY: u32 = WM_APP + 2;
/// 退出清理做完 → 回到 UI 线程销毁窗口
const WM_APP_QUIT: u32 = WM_APP + 3;

const TRAY_ID: u32 = 1;

// 菜单项 ID 与控件 ID 同在 WM_COMMAND 里分发，所以用同一种类型 i32
const IDM_SHOW: i32 = 2001;
const IDM_CONNECT: i32 = 2002;
const IDM_DISCONNECT: i32 = 2003;
const IDM_EXIT: i32 = 2004;

fn tray_tip(online: bool) -> &'static str {
    if online {
        "Mentorust · 已连接（后台保活中）"
    } else {
        "Mentorust · 未连接"
    }
}

/// 在内存里画一个 32×32 圆点图标 —— 省掉 .ico 资源和 build script，
/// 最终 exe 仍然只有一个文件。
///
/// 返回 `CreateIconFromResourceEx` 要的「单个图标资源」格式：
/// BITMAPINFOHEADER(40B) + BGRA 像素（自下而上）+ AND 掩码。
fn icon_bits(r: u8, g: u8, b: u8) -> Vec<u8> {
    const S: i32 = 32;
    let mut v: Vec<u8> = Vec::with_capacity(40 + (S * S * 4) as usize + (S * 4) as usize);

    // BITMAPINFOHEADER：biHeight 要写成「高 × 2」（XOR 像素图 + AND 掩码）
    for x in [40i32, S, S * 2] {
        v.extend_from_slice(&(x as u32).to_le_bytes());
    }
    v.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    v.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
    for _ in 0..6 {
        // biCompression=BI_RGB, biSizeImage, biXPelsPerMeter, biYPelsPerMeter,
        // biClrUsed, biClrImportant —— 全 0
        v.extend_from_slice(&0u32.to_le_bytes());
    }

    // 像素：自下而上，BGRA。半径 13，最外 1.5px 用 alpha 渐变做抗锯齿。
    let c = (S as f32 - 1.0) / 2.0;
    for y in (0..S).rev() {
        for x in 0..S {
            let d = ((x as f32 - c).powi(2) + (y as f32 - c).powi(2)).sqrt();
            let a = if d <= 12.0 {
                255.0
            } else if d >= 13.5 {
                0.0
            } else {
                (13.5 - d) / 1.5 * 255.0
            };
            // 外圈压暗一点，缩到 16px 显示时也有立体感、不至于糊成一坨
            let k = if d > 11.2 { 0.76 } else { 1.0 };
            v.push((b as f32 * k) as u8);
            v.push((g as f32 * k) as u8);
            v.push((r as f32 * k) as u8);
            v.push(a as u8);
        }
    }
    // AND 掩码：32 位/行 = 4 字节，共 S 行，全 0（带 alpha 的图不看掩码）
    v.resize(v.len() + (S * 4) as usize, 0);
    v
}

/// 取（首次则创建）指定状态的托盘图标
unsafe fn tray_icon(online: bool) -> HICON {
    let slot = if online { &ICON_ON } else { &ICON_OFF };
    let cached = slot.load(Ordering::SeqCst);
    if cached != 0 {
        return HICON(cached as *mut c_void);
    }
    // 绿 = 已连接，灰 = 未连接（红绿在托盘小图标上区分度不如绿/灰）
    let (r, g, b) = if online {
        (0x2eu8, 0xc4u8, 0x74u8)
    } else {
        (0x9au8, 0xa0u8, 0xa6u8)
    };
    let bits = icon_bits(r, g, b);
    let icon = CreateIconFromResourceEx(&bits, BOOL(1), 0x0003_0000, 32, 32, LR_DEFAULTCOLOR)
        .unwrap_or(HICON(ptr::null_mut()));
    slot.store(icon.0 as isize, Ordering::SeqCst);
    icon
}

/// 组装一份 NOTIFYICONDATAW（字段多，集中填一次）
unsafe fn tray_data(hwnd: HWND, online: bool) -> NOTIFYICONDATAW {
    let mut nid = NOTIFYICONDATAW::default();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ID;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = tray_icon(online);
    let w: Vec<u16> = tray_tip(online).encode_utf16().collect();
    let n = w.len().min(nid.szTip.len() - 1);
    nid.szTip[..n].copy_from_slice(&w[..n]);
    nid
}

/// 挂上托盘图标（窗口建好后调用一次）
unsafe fn tray_add(hwnd: HWND) {
    if TRAY_ADDED.load(Ordering::SeqCst) {
        return;
    }
    let online = ONLINE.load(Ordering::SeqCst);
    let nid = tray_data(hwnd, online);
    if Shell_NotifyIconW(NIM_ADD, &nid).as_bool() {
        TRAY_ADDED.store(true, Ordering::SeqCst);
        TRAY_SHOWN_ONLINE.store(online, Ordering::SeqCst);
        log::info!("[TRAY] 托盘图标已挂上（点 X 最小化到托盘，退出走右键菜单）");
    } else {
        log::warn!("[TRAY] 托盘图标挂载失败（Shell_NotifyIcon 返回 false）");
    }
}

/// 在线状态变了才刷新图标与提示文字
unsafe fn sync_tray(hwnd: HWND) {
    if !TRAY_ADDED.load(Ordering::SeqCst) {
        return;
    }
    let online = ONLINE.load(Ordering::SeqCst);
    if online == TRAY_SHOWN_ONLINE.load(Ordering::SeqCst) {
        return;
    }
    let nid = tray_data(hwnd, online);
    if Shell_NotifyIconW(NIM_MODIFY, &nid).as_bool() {
        TRAY_SHOWN_ONLINE.store(online, Ordering::SeqCst);
    }
}

unsafe fn tray_remove(hwnd: HWND) {
    if !TRAY_ADDED.swap(false, Ordering::SeqCst) {
        return;
    }
    let nid = tray_data(hwnd, false);
    let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
}

/// 托盘气泡提示（"已最小化到托盘"这类一次性说明用）
unsafe fn tray_balloon(hwnd: HWND, title: &str, text: &str) {
    if !TRAY_ADDED.load(Ordering::SeqCst) {
        return;
    }
    let mut nid = tray_data(hwnd, ONLINE.load(Ordering::SeqCst));
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = NIIF_INFO;
    let t: Vec<u16> = title.encode_utf16().collect();
    let n = t.len().min(nid.szInfoTitle.len() - 1);
    nid.szInfoTitle[..n].copy_from_slice(&t[..n]);
    let m: Vec<u16> = text.encode_utf16().collect();
    let n = m.len().min(nid.szInfo.len() - 1);
    nid.szInfo[..n].copy_from_slice(&m[..n]);
    nid.Anonymous.uTimeout = 6000;
    let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
}

/// 从托盘唤回主界面（窗口只是隐藏了，控件状态都还在）
unsafe fn show_main(hwnd: HWND) {
    let _ = ShowWindow(hwnd, SW_SHOW);
    let _ = SetForegroundWindow(hwnd);
}

/// 托盘右键菜单
unsafe fn tray_menu(hwnd: HWND) {
    let Ok(menu) = CreatePopupMenu() else {
        return;
    };
    let online = ONLINE.load(Ordering::SeqCst);
    let busy = BUSY.load(Ordering::SeqCst);

    let s_show = wide("打开主界面");
    let s_conn = wide("立即连接");
    let s_disc = wide("断开连接");
    let s_exit = wide("退出（并断开认证）");

    let _ = AppendMenuW(menu, MF_STRING, IDM_SHOW as usize, PCWSTR(s_show.as_ptr()));
    // 已在线就没必要再「连接」；正在连接/断开时两项都置灰，避免重复触发
    let f_conn = if online || busy {
        MENU_ITEM_FLAGS(MF_STRING.0 | MF_GRAYED.0)
    } else {
        MF_STRING
    };
    let _ = AppendMenuW(menu, f_conn, IDM_CONNECT as usize, PCWSTR(s_conn.as_ptr()));
    let f_disc = if busy {
        MENU_ITEM_FLAGS(MF_STRING.0 | MF_GRAYED.0)
    } else {
        MF_STRING
    };
    let _ = AppendMenuW(menu, f_disc, IDM_DISCONNECT as usize, PCWSTR(s_disc.as_ptr()));
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, IDM_EXIT as usize, PCWSTR(s_exit.as_ptr()));

    // TrackPopupMenu 之前必须把窗口提到前台，否则点到菜单外面菜单不消失
    // （微软文档明确要求 SetForegroundWindow + 事后 PostMessage(WM_NULL)）
    let mut pt = windows::Win32::Foundation::POINT::default();
    let _ = GetCursorPos(&mut pt);
    let _ = SetForegroundWindow(hwnd);
    let _ = TrackPopupMenu(
        menu,
        TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
        pt.x,
        pt.y,
        0,
        hwnd,
        None,
    );
    let _ = PostMessageW(hwnd, WM_NULL, WPARAM(0), LPARAM(0));
    let _ = DestroyMenu(menu);
}

/// 「退出」：注销会话 → 结束后台认证进程 → 关窗口。
///
/// 这是唯一会真的停掉保活并断网的入口。点 X 只是藏到托盘，两件事必须分开，
/// 否则用户关个窗口就把网断了。
unsafe fn tray_exit(hwnd: HWND) {
    if EXITING.swap(true, Ordering::SeqCst) {
        return;
    }
    tray_remove(hwnd);
    let nic = current_nic();
    say_status("○ 正在退出...");
    log::info!("[TRAY] 从托盘退出：注销会话并结束后台保活");
    thread::spawn(move || {
        // logoff() 内部先 kill_ghosts()、再向 BRAS 发 EAPOL-Logoff。
        // 不注销直接杀进程会留下半开坏会话，下次要等 BRAS 超时才连得上。
        crate::logoff(&nic);
        let h = MAIN_HWND.load(Ordering::SeqCst);
        if h != 0 {
            unsafe {
                let _ = PostMessageW(HWND(h as *mut c_void), WM_APP_QUIT, WPARAM(0), LPARAM(0));
            }
        }
    });
}

// ===== 窗口过程 =====

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            let note = ((wparam.0 >> 16) & 0xFFFF) as u32;
            match id {
                ID_BTN_CONNECT => start_connect(hwnd),
                ID_BTN_DISCONNECT => start_disconnect(hwnd),
                ID_AUTOSTART => {
                    let on = checkbox_checked(hwnd, ID_AUTOSTART);
                    if set_autostart(on) {
                        say_log(if on {
                            "已启用开机自启动（下次开机自动打开本界面）"
                        } else {
                            "已关闭开机自启动"
                        });
                    } else {
                        say_log("写入开机自启动失败（可能被安全软件拦截）");
                    }
                    // 关掉自启动 → 「自动连接」置灰并取消勾选
                    apply_options(hwnd, on, on && auto_connect_now());
                    let (u, p) = (get_text(hwnd, ID_USER), get_text(hwnd, ID_PASS));
                    save_config(&u, &p, &current_nic(), auto_connect_now());
                }
                ID_AUTOCONNECT => {
                    let on = checkbox_checked(hwnd, ID_AUTOCONNECT);
                    *AUTO_CONNECT.lock().unwrap() = on;
                    say_log(if on {
                        "已启用「自动连接」：开机后自动联网"
                    } else {
                        "已关闭「自动连接」：开机后只开界面，需手动点「连接」"
                    });
                    let (u, p) = (get_text(hwnd, ID_USER), get_text(hwnd, ID_PASS));
                    save_config(&u, &p, &current_nic(), on);
                }
                ID_NIC => {
                    if note == CBN_SELCHANGE {
                        on_nic_changed(hwnd);
                    } else if note == CBN_DROPDOWN {
                        // 每次展开都重扫一遍：插拔网线 / 拿到新地址能立刻看到
                        if let Ok(c) = GetDlgItem(hwnd, ID_NIC) {
                            reload_nics(c);
                        }
                    }
                }
                // ---- 托盘菜单项 ----
                IDM_SHOW => show_main(hwnd),
                IDM_CONNECT => {
                    show_main(hwnd); // 先亮出界面，让用户看到"连接中..."
                    start_connect(hwnd);
                }
                IDM_DISCONNECT => start_disconnect(hwnd),
                IDM_EXIT => tray_exit(hwnd),
                _ => {}
            }
            LRESULT(0)
        }
        WM_APP_PUMP => {
            pump(hwnd);
            LRESULT(0)
        }
        // 托盘图标被点：lParam 是鼠标消息
        WM_TRAY => {
            match lparam.0 as u32 {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => show_main(hwnd),
                WM_RBUTTONUP | WM_CONTEXTMENU => tray_menu(hwnd),
                _ => {}
            }
            LRESULT(0)
        }
        // 退出流程已注销会话、停掉后台进程 → 这里才真的销毁窗口
        WM_APP_QUIT => {
            tray_remove(hwnd);
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_CLOSE => {
            if EXITING.load(Ordering::SeqCst) {
                let _ = DestroyWindow(hwnd);
            } else {
                // 点 X = 藏到托盘，后台认证 / 心跳继续跑，网络不受影响。
                // 要真的停下来（并断网）走托盘菜单的「退出」。
                let _ = ShowWindow(hwnd, SW_HIDE);
                if !TRAY_HINTED.swap(true, Ordering::SeqCst) {
                    tray_balloon(
                        hwnd,
                        "Mentorust 仍在后台保活",
                        "窗口已收到托盘，网络不会断。要彻底退出（含断开认证），请右键托盘图标 →「退出」。",
                    );
                }
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

// ===== 建控件 =====

#[allow(clippy::too_many_arguments)]
unsafe fn make_child(
    parent: HWND,
    class: &str,
    text: &str,
    style: WINDOW_STYLE,
    exstyle: WINDOW_EX_STYLE,
    id: i32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    hinst: HINSTANCE,
) -> HWND {
    let cls = wide(class);
    let txt = wide(text);
    let hwnd = CreateWindowExW(
        exstyle,
        PCWSTR(cls.as_ptr()),
        PCWSTR(txt.as_ptr()),
        style | WS_CHILD | WS_VISIBLE,
        x,
        y,
        w,
        h,
        parent,
        HMENU(id as isize as *mut c_void),
        hinst,
        None,
    )
    .unwrap_or(HWND(ptr::null_mut()));
    if !hwnd.0.is_null() {
        let font = GetStockObject(DEFAULT_GUI_FONT);
        SendMessageW(hwnd, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    }
    hwnd
}

/// 打开图形界面并进入消息循环（阻塞直到窗口关闭）
pub fn run() {
    unsafe {
        // 双击启动时摆脱自带的控制台窗口
        let _ = FreeConsole();

        let cls = wide(CLASS_NAME);

        // 单实例：已有窗口则把它提到前台，然后退出。
        // 注意必须 ShowWindow —— 窗口可能正藏在托盘里（隐藏态下 SetForegroundWindow 没效果，
        // 用户会以为"双击没反应"）。
        if let Ok(old) = FindWindowW(PCWSTR(cls.as_ptr()), PCWSTR::null()) {
            if !old.0.is_null() {
                let _ = ShowWindow(old, SW_SHOW);
                let _ = SetForegroundWindow(old);
                return;
            }
        }

        let hinst = match GetModuleHandleW(PCWSTR::null()) {
            Ok(h) => HINSTANCE(h.0),
            Err(_) => return,
        };

        let mut wc = WNDCLASSW::default();
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = hinst;
        wc.hCursor = LoadCursorW(HINSTANCE(ptr::null_mut()), IDC_ARROW).unwrap_or_default();
        wc.hbrBackground = CreateSolidBrush(COLORREF(0x00FFFFFF));
        wc.lpszClassName = PCWSTR(cls.as_ptr());
        RegisterClassW(&wc);

        // ---- 窗口：固定小尺寸（不可缩放），创建后按外框差量精确定位并居中 ----
        let win_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        let title = wide(WIN_TITLE);
        let hwnd = match CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(cls.as_ptr()),
            PCWSTR(title.as_ptr()),
            win_style,
            0,
            0,
            CLIENT_W,
            CLIENT_H,
            HWND(ptr::null_mut()),
            HMENU(ptr::null_mut()),
            hinst,
            None,
        ) {
            Ok(h) => h,
            Err(_) => return,
        };
        // 「外框 − 客户区」的差量在任何 DPI / 主题下都成立，比硬编码高度可靠
        {
            let mut wr = RECT { left: 0, top: 0, right: 0, bottom: 0 };
            let mut cr = RECT { left: 0, top: 0, right: 0, bottom: 0 };
            let _ = GetWindowRect(hwnd, &mut wr);
            let _ = GetClientRect(hwnd, &mut cr);
            let ww = CLIENT_W + ((wr.right - wr.left) - (cr.right - cr.left));
            let wh = CLIENT_H + ((wr.bottom - wr.top) - (cr.bottom - cr.top));
            let x = (GetSystemMetrics(SM_CXSCREEN) - ww) / 2;
            let y = (GetSystemMetrics(SM_CYSCREEN) - wh) / 2;
            let _ = SetWindowPos(
                hwnd,
                HWND(ptr::null_mut()),
                x,
                y,
                ww,
                wh,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
        MAIN_HWND.store(hwnd.0 as isize, Ordering::SeqCst);

        // ---- 配置：账号 / 密码 / 上次选的网卡 ----
        // 网卡要在建下拉框之前恢复，否则不知道默认该选哪一项
        let cfg = load_config();
        let cfg_user = cfg.user.clone();
        let cfg_pass = cfg.pass.clone();
        let cfg_autoconnect = cfg.autoconnect;
        *NIC_SEL.lock().unwrap() = cfg.nic.clone();

        // ---- 控件：三行输入（账号 / 密码 / 网卡）+ 一排按钮 + 一行信息（越小越好） ----
        make_child(hwnd, "STATIC", "账号", WINDOW_STYLE(0), WINDOW_EX_STYLE(0), 0, M, 13, 34, 18, hinst);
        make_child(hwnd, "EDIT", "", ST_EDIT, WINDOW_EX_STYLE(0), ID_USER, M + 38, 10, CW, 22, hinst);

        make_child(hwnd, "STATIC", "密码", WINDOW_STYLE(0), WINDOW_EX_STYLE(0), 0, M, 41, 34, 18, hinst);
        make_child(hwnd, "EDIT", "", ST_EDIT_PASS, WINDOW_EX_STYLE(0), ID_PASS, M + 38, 38, CW, 22, hinst);

        make_child(hwnd, "STATIC", "网卡", WINDOW_STYLE(0), WINDOW_EX_STYLE(0), 0, M, 69, 34, 18, hinst);
        let combo = make_child(hwnd, "COMBOBOX", "", ST_COMBO, WINDOW_EX_STYLE(0), ID_NIC,
            M + 38, 66, CW, 200, hinst);
        // 下拉列表允许比控件更宽，长描述才看得全
        SendMessageW(combo, CB_SETDROPPEDWIDTH, WPARAM(430), LPARAM(0));

        let bw = (CW - 16) / 2;
        make_child(hwnd, "BUTTON", "连  接", ST_BTN_DEF, WINDOW_EX_STYLE(0), ID_BTN_CONNECT, M, 98, bw, 26, hinst);
        make_child(hwnd, "BUTTON", "断  开", ST_BTN, WINDOW_EX_STYLE(0), ID_BTN_DISCONNECT, M + bw + 16, 98, bw, 26, hinst);

        // ---- 一行选项：开机自启动 / 自动连接（后者只在自启动启用时可勾） ----
        make_child(hwnd, "BUTTON", "开机自启动", ST_CHK, WINDOW_EX_STYLE(0), ID_AUTOSTART,
            M, 130, 120, 18, hinst);
        make_child(hwnd, "BUTTON", "自动连接", ST_CHK, WINDOW_EX_STYLE(0), ID_AUTOCONNECT,
            M + 126, 130, 116, 18, hinst);

        make_child(hwnd, "EDIT", "", ST_INFO,
            WINDOW_EX_STYLE(WS_EX_CLIENTEDGE.0), ID_INFO, M, 154, CW + 38, 22, hinst);

        // 填入网卡列表（默认选中上次用的那张）
        reload_nics(combo);

        // ---- 填入账号密码 ----
        set_text(hwnd, ID_USER, &cfg_user);
        set_text(hwnd, ID_PASS, &cfg_pass);

        let _ = ShowWindow(hwnd, SW_SHOW);
        // 挂托盘图标：关窗后程序仍在此驻留（图标 + 菜单是唯一入口）
        tray_add(hwnd);
        say_status("○ 未连接");
        say_log("填好账号密码点「连接」");

        // ---- 开机自启动：恢复两个复选框的勾选 / 联动，必要时自动发起连接 ----
        // 自启动状态以注册表为准；ini 里的 autoconnect 只是「意愿」，还要自启动开着才生效。
        let autostart = autostart_on();
        apply_options(hwnd, autostart, cfg_autoconnect);
        if autostart {
            // exe 可能被挪过位置 → 顺手把 Run 项刷新成当前路径（否则开机拉起的是旧位置）
            set_autostart(true);
        }
        if STARTUP_LAUNCH.load(Ordering::SeqCst) && autostart && cfg_autoconnect {
            say_log("开机自启动：正在自动连接...");
            start_connect(hwnd);
        }

        // 启动时立刻探测一次当前状态（只刷状态，不覆盖上面那句提示）
        thread::spawn(|| {
            let online = crate::campus_online(&current_nic());
            ONLINE.store(online, Ordering::SeqCst);
            say_status(if online { "● 已连接" } else { "○ 未连接" });
        });

        // 之后每 3 秒刷新一次状态栏：掉线和后台自动重连都能实时看到。
        // 判据加阻尼：**连续 2 次探测失败**才显示「未连接」—— 单次探测可能撞上
        // 瞬时丢包（认证刚成功的窗口期尤其如此），一次假失败就翻脸会让界面乱跳，
        // 用户会以为掉线了（其实后台还好好的）。
        thread::spawn(|| {
            let mut down_strikes = 0u32;
            loop {
                thread::sleep(Duration::from_secs(3));
                if BUSY.load(Ordering::SeqCst) {
                    down_strikes = 0;
                    continue; // 正在手动连接/断开，别抢状态栏
                }
                let online = crate::campus_online(&current_nic());
                ONLINE.store(online, Ordering::SeqCst);
                if online {
                    down_strikes = 0;
                } else {
                    down_strikes = down_strikes.saturating_add(1);
                }
                if crate::stop_flag_set() {
                    // 用户手动断开后处于"停用"状态：不会自动重连
                    say_status(if online {
                        "○ 已断开（手动）· 仍有网络"
                    } else {
                        "○ 已断开（手动）"
                    });
                } else if online {
                    say_status("● 已连接");
                } else if down_strikes >= 2 {
                    say_status("○ 未连接");
                }
                // down_strikes == 1 时保持上一次显示，避免瞬时抖动让界面乱跳
            }
        });

        // ---- 消息循环 ----
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, HWND(ptr::null_mut()), 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        MAIN_HWND.store(0, Ordering::SeqCst);
    }
}
