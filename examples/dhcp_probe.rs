//! 实跑探针：验证「照官方做的」DHCP 管理这条链路真的能用。
//!
//! 直接用 `#[path]` 引入 `src/dhcp.rs` **同一份源码**（不复制、不改写），
//! 因此这里跑通就等于认证流程里跑通。
//!
//! 覆盖三件事：
//!   1. `GetIfTable2` / `FreeMibTable` 通路正常，能列出全部接口；
//!   2. 按 **MAC** 反查 ifIndex —— 这是 main.rs 认证前实际走的路径
//!      （pnet 的 `\Device\NPF_{GUID}` 与 `MIB_IF_ROW2.Alias` 对不上，必须靠 MAC）；
//!   3. 实调一次 `IpRenewAddress()` —— 官方 `CDhcpThread::RenewDhcpAddr`
//!      做的正是这件事，续租租约无副作用。
//!
//! 用法: cargo run --release --example dhcp_probe
//!      dhcp_probe [nic_name] [mac_hex]

#[path = "../src/dhcp.rs"]
mod dhcp;

use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let nic = args.get(1).cloned().unwrap_or_default();
    let mac_s = args.get(2).cloned().unwrap_or_default();

    println!("=== 1. 接口表 ===");
    #[cfg(windows)]
    unsafe {
        use windows::Win32::NetworkManagement::IpHelper::{
            FreeMibTable, GetIfTable2, MIB_IF_TABLE2,
        };
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        let err = GetIfTable2(&mut table);
        println!("GetIfTable2 -> {:?}", err);
        if err == windows::Win32::Foundation::WIN32_ERROR(0) && !table.is_null() {
            let n = (*table).NumEntries as usize;
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
            for r in rows {
                let alias: Vec<u16> = r.Alias.iter().copied().take_while(|c| *c != 0).collect();
                let alias = String::from_utf16_lossy(&alias);
                let len = (r.PhysicalAddressLength as usize).min(r.PhysicalAddress.len());
                println!(
                    "  ifIndex={:<4} alias={:<24} mac={:02x?}",
                    r.InterfaceIndex, alias, &r.PhysicalAddress[..len]
                );
            }
            FreeMibTable(table as *const core::ffi::c_void);
        }
    }

    println!("\n=== 2. MAC 反查 ifIndex ===");
    let mac_bytes: Option<[u8; 6]> = if mac_s.is_empty() {
        None
    } else {
        let cleaned: String = mac_s.chars().filter(|c| *c != ':' && *c != '-').collect();
        hex::decode(cleaned).ok().and_then(|v| {
            if v.len() == 6 {
                let mut a = [0u8; 6];
                a.copy_from_slice(&v);
                Some(a)
            } else {
                None
            }
        })
    };
    println!("  目标网卡名 = {:?}", nic);
    println!("  目标 MAC   = {:?}", mac_bytes.map(|m| format!("{:02x?}", m)));
    match dhcp::if_index_of(&nic, mac_bytes.as_ref().map(|m| &m[..])) {
        Some(idx) => println!("  [OK] 反查命中 ifIndex={}", idx),
        None => println!("  [--] 未命中"),
    }

    println!("\n=== 3. IpRenewAddress 实跑 ===");
    match dhcp::renew_dhcp(&nic, mac_bytes.as_ref().map(|m| &m[..])) {
        Ok(code) => println!("  [OK] 续租成功 code={}", code),
        Err(code) => println!("  [--] 续租返回 0x{:X}", code),
    }

    println!("\n=== 4. 等待地址下发（最多 10 秒）===");
    match dhcp::wait_dhcp_ready(&nic, Duration::from_secs(10)) {
        Some(ip) => println!("  [OK] 拿到地址 {}", ip),
        None => println!("  [--] 10 秒内未拿到 10.x（网卡可能没接网线）"),
    }
}
