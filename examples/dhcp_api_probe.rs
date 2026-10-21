//! 穷举 IpRenewAddress 的参数组合，确定在 Windows 10/11 上正确的调用方式。
//!
//! 背景：官方 6.41 客户端用 2015 年的 `GetInterfaceInfo` + 老 `MIB_IFROW`，
//! 而 windows-rs 0.58 暴露的是新版 `GetIfTable2` + `IP_ADAPTER_INDEX_MAP`。
//! 实测把 pcap 路径塞进 Name 会得到 0x7B；Name 置 NULL + 正确的物理 ifIndex
//! 得到 0x57 —— 需要确定到底哪个字段要怎么填。
//!
//! 用法: cargo run --release --example dhcp_api_probe [ifIndex]

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, IpRenewAddress, IP_ADAPTER_INDEX_MAP, MIB_IF_TABLE2,
};

fn main() {
    let arg: Option<u32> = std::env::args().nth(1).and_then(|s| s.parse().ok());
    let want_index = arg.unwrap_or(7);

    unsafe {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        let err = GetIfTable2(&mut table);
        assert_eq!(err, WIN32_ERROR(0));
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);

        let mut alias_of_target = String::new();
        for r in rows {
            if r.InterfaceIndex == want_index {
                let a: Vec<u16> = r.Alias.iter().copied().take_while(|c| *c != 0).collect();
                alias_of_target = String::from_utf16_lossy(&a);
                println!("目标 ifIndex={} alias={:?}", r.InterfaceIndex, alias_of_target);
            }
        }

        // 变体 1：Name = NULL
        let m1 = IP_ADAPTER_INDEX_MAP { Index: want_index, Name: [0u16; 128] };
        println!("[1] Index={} Name=NULL          -> 0x{:X}", want_index, IpRenewAddress(&m1));

        // 变体 2：Name = 别名（"以太网"）
        let mut nm = [0u16; 128];
        for (i, c) in alias_of_target.encode_utf16().enumerate() {
            if i >= 127 { break; }
            nm[i] = c;
        }
        let m2 = IP_ADAPTER_INDEX_MAP { Index: want_index, Name: nm };
        println!("[2] Index={} Name=alias          -> 0x{:X}", want_index, IpRenewAddress(&m2));

        // 变体 3：Name = 空串（首字节 0，等同 NULL）
        let m3 = IP_ADAPTER_INDEX_MAP { Index: want_index, Name: [0u16; 128] };
        println!("[3] Index={} Name=empty          -> 0x{:X}", want_index, IpRenewAddress(&m3));

        // 变体 4：把 IP_INTERFACE_INFO / GetInterfaceInfo 老路子的结果也看一眼
        let mut buf = [0u8; 0x108];
        let mut size: u32 = 0x108;
        let r = windows::Win32::NetworkManagement::IpHelper::GetInterfaceInfo(
            Some(buf.as_mut_ptr() as *mut windows::Win32::NetworkManagement::IpHelper::IP_INTERFACE_INFO),
            &mut size,
        );
        println!("[4] GetInterfaceInfo(0x108)      -> 0x{:X} (size={})", r, size);

        FreeMibTable(table as *const core::ffi::c_void);
    }
}
