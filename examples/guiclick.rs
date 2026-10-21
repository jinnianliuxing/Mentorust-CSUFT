//! GUI 自动化测试工具（开发期使用，不参与正式功能）
//!
//! 用法：
//!   guiclick.exe <控件ID>   向按钮发点击命令（1003=连接 1004=断开）
//!   guiclick.exe dump       读取界面上的状态与日志文字

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetDlgItem, SendMessageW, WM_COMMAND, WM_GETTEXT,
};
use windows::core::PCWSTR;

const ID_STATUS: i32 = 1005;
const ID_LOG: i32 = 1006;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 跨进程读取控件文字。
/// 注意：GetWindowText 对**其它进程**的 EDIT 控件只会返回窗口标题（通常为空），
/// 必须显式发 WM_GETTEXT 消息才能拿到真实内容。
unsafe fn text_of(hwnd: HWND, id: i32) -> String {
    let Ok(c) = GetDlgItem(hwnd, id) else {
        return "<无此控件>".into();
    };
    let mut buf = vec![0u16; 8192];
    let n = SendMessageW(
        c,
        WM_GETTEXT,
        WPARAM(buf.len()),
        LPARAM(buf.as_mut_ptr() as isize),
    );
    let n = n.0 as usize;
    if n == 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..n.min(buf.len())])
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "dump".to_string());

    unsafe {
        let cls = wide("MentorustGuiWndClass");
        let hwnd = match FindWindowW(PCWSTR(cls.as_ptr()), PCWSTR::null()) {
            Ok(h) if !h.0.is_null() => h,
            _ => {
                println!("未找到 Mentorust 窗口");
                std::process::exit(1);
            }
        };

        if arg == "dump" {
            println!("窗口句柄 = {:?}", hwnd.0);
            println!("[状态] {}", text_of(hwnd, ID_STATUS));
            println!("[日志]\n{}", text_of(hwnd, ID_LOG));
            return;
        }

        let id: i32 = arg.parse().unwrap_or(1003);
        let btn = GetDlgItem(hwnd, id).unwrap_or(HWND(std::ptr::null_mut()));
        if btn.0.is_null() {
            println!("未找到控件 {}", id);
            std::process::exit(1);
        }
        SendMessageW(hwnd, WM_COMMAND, WPARAM(id as usize), LPARAM(btn.0 as isize));
        println!("已向控件 {} 发送点击命令", id);
    }
}
