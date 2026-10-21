//! 锐捷官方客户端（CSUFT_Supplicant_For_Windows_V6.41）的 DHCP 管理实现。
//!
//! 逆向依据 —— `8021x.exe` (x64) 的 Ghidra 12.1.4 伪代码：
//!
//! | 官方函数            | 反编译出的行为                        | 对应本模块       |
//! |---------------------|---------------------------------------|------------------|
//! | `FUN_1400A95C0`     | `CDhcpThread::RenewDhcpAddr` → `IpRenewAddress()`  | `renew_dhcp`  |
//! | `FUN_1400A97F0`     | `IpReleaseAddress()`（释放租约）        | `release_dhcp`|
//! | `FUN_14018BC90`     | `"\ipconfig.exe /renew"`（备用路径）    | —（用 API 替代）|
//! | `FUN_14006D730`     | 认证流程内 `"Release IP wired"` → 释放 + InitDhcp | 见 `main.rs` |
//! | `FUN_1401D3580`     | `CUserConfig` 读 `[DHCPMODE] EnableBeforeAuth` | 见 `main.rs` |
//!
//! 官方自封的返回码：`50000` 成功 / `0xC352` 参数非法 / `0xC351` 取网卡信息失败 /
//! `0xC353` 接口表里找不到该网卡。Windows API 自身返回 `0` 表示成功，
//! 本模块统一包装成官方的 `50000` 语义。
//!
//! ## 为什么要照官方这么做
//!
//! 实测（2026-10-20）：**认证时网卡处于 APIPA(169.254.x.x) 建立的会话，会被 BRAS
//! 在 3600 s 准点踢掉**；而建立时已经持有 `10.x` 的会话能活 87~207 分钟。
//!
//! 官方客户端的对策就是 `[DHCPMODE] EnableBeforeAuth=1` —— **认证之前就启动 DHCP**，
//! 让 EAPOL 握手发生在一个已经持有合法租约的状态上；必要时在认证流程内部直接
//! `IpReleaseAddress()` + 重新 InitDhcp，把地址彻底翻新。
//!
//! 本项目自己实现 EAPOL 握手（不经过 Windows 的 802.1X 引擎），EAP 响应帧用
//! 网卡 IPv4 作源 IP —— 带着 APIPA 去认证既会发出源地址非法的帧，也会把会话
//! 建立成那种短命的。所以官方这套 DHCP 管理必须照搬。

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// 官方语义：续租成功
pub const DHCP_OK: u32 = 50000;
/// 官方语义：参数非法（例如网卡索引为 0）
pub const DHCP_ERR_PARAM: u32 = 0xC352;
/// 官方语义：取网卡信息失败
pub const DHCP_ERR_IFINFO: u32 = 0xC351;
/// 官方语义：接口表里找不到该网卡
pub const DHCP_ERR_NOTFOUND: u32 = 0xC353;

#[cfg(windows)]
mod imp {
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, IpReleaseAddress, IpRenewAddress, IP_ADAPTER_INDEX_MAP,
        MIB_IF_ROW2, MIB_IF_TABLE2,
    };

    /// 枚举本机所有网络接口，回调里挑出需要的行。
    ///
    /// `GetIfTable2` 由系统分配内存，**必须**用 `FreeMibTable` 归还，
    /// 否则每次调用都会泄漏一块内核态拷贝。
    pub(super) unsafe fn with_if_rows<F, R>(f: F) -> Option<R>
    where
        F: FnOnce(&[MIB_IF_ROW2]) -> R,
    {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        let err = GetIfTable2(&mut table);
        if err != WIN32_ERROR(0) || table.is_null() {
            return None;
        }
        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        let out = f(rows);
        FreeMibTable(table as *const core::ffi::c_void);
        Some(out)
    }

    /// `IP_ADAPTER_INDEX_MAP.Name` 按 MSDN 规定**一律传 NULL**。
    ///
    /// 实测踩坑：把 pcap 的路径（`\Device\NPF_{GUID}`）塞进这个字段，
    /// IpRenewAddress 会返回 0x7B（ERROR_INVALID_NAME）。这个字段只作占位，
    /// 真正定位接口靠 `Index`。
    fn null_name() -> [u16; 128] {
        [0u16; 128]
    }

    pub(super) unsafe fn renew(index: u32, _name: &str) -> u32 {
        let map = IP_ADAPTER_INDEX_MAP {
            Index: index,
            Name: null_name(),
        };
        IpRenewAddress(&map)
    }

    pub(super) unsafe fn release(index: u32, _name: &str) -> u32 {
        let map = IP_ADAPTER_INDEX_MAP {
            Index: index,
            Name: null_name(),
        };
        IpReleaseAddress(&map)
    }
}

/// 找出网卡的接口索引（`MIB_IF_ROW2.InterfaceIndex`）。
///
/// 优先按 **MAC 地址**匹配 —— 网卡名在 pnet / Windows / GUI 三处的口径未必一致
/// （pnet 给的是注册表 AdapterName，`MIB_IF_ROW2.Alias` 给的是友好名），
/// 而 MAC 是唯一稳定的标识。匹配不到再退回按名字匹配。
pub fn if_index_of(nic_name: &str, mac: Option<&[u8]>) -> Option<u32> {
    #[cfg(windows)]
    unsafe {
        return imp::with_if_rows(|rows| {
            // 1) 名字完全对得上优先 —— 用户选的就是这个接口。
            let want = nic_name.to_string();
            for row in rows {
                let alias = wide_str(&row.Alias);
                let desc = wide_str(&row.Description);
                if (!want.is_empty() && (alias == want || desc == want)) && is_physical_eth(row.Type, &alias) {
                    return Some(row.InterfaceIndex);
                }
            }
            for row in rows {
                let alias = wide_str(&row.Alias);
                let desc = wide_str(&row.Description);
                if !want.is_empty() && (alias == want || desc == want) {
                    return Some(row.InterfaceIndex);
                }
            }

            // 2) 名字对不上就按 MAC 找。同一张物理网卡会以多个 mini-port 出现
            //    （WFP / Npcap / QoS 过滤驱动都共用同一个 MAC），必须挑物理口，
            //    否则 IpRenewAddress 会打给过滤驱动而失败。
            if let Some(want_mac) = mac {
                let mut fallback = None;
                for row in rows {
                    let len = row.PhysicalAddressLength as usize;
                    if len != 6 || len > row.PhysicalAddress.len() {
                        continue;
                    }
                    if &row.PhysicalAddress[..len] != want_mac {
                        continue;
                    }
                    let alias = wide_str(&row.Alias);
                    if is_physical_eth(row.Type, &alias) {
                        return Some(row.InterfaceIndex);
                    }
                    if fallback.is_none() {
                        fallback = Some(row.InterfaceIndex);
                    }
                }
                if fallback.is_some() {
                    return fallback;
                }
            }
            None
        })
        .flatten();
    }
    #[cfg(not(windows))]
    {
        let _ = (nic_name, mac);
        None
    }
}

/// 把定长 UTF-16 缓冲转成去掉尾部 NUL 的 String。
#[cfg(windows)]
fn wide_str(buf: &[u16]) -> String {
    let v: Vec<u16> = buf.iter().copied().take_while(|c| *c != 0).collect();
    String::from_utf16_lossy(&v)
}

/// 判断是不是**物理以太网口**（而不是 WFP/Npcap/QoS 过滤驱动的小端口）。
///
/// `MIB_IF_TYPE_ETHERNET` = 6；过滤驱动的 mini-port 类型不是 6，
/// 且别名里会带 "Filter" / "WFP" / "Npcap" / "QoS" 之类的后缀。
#[cfg(windows)]
fn is_physical_eth(if_type: u32, alias: &str) -> bool {
    const MIB_IF_TYPE_ETHERNET: u32 = 6;
    if if_type != MIB_IF_TYPE_ETHERNET {
        return false;
    }
    const FILTER_HINTS: [&str; 6] = ["Filter", "WFP", "Npcap", "NPCAP", "QoS", "Hyper-V"];
    !FILTER_HINTS.iter().any(|h| alias.contains(h))
}

/// 主动续租该网卡的 DHCP 租约 —— 官方 `CDhcpThread::RenewDhcpAddr` 的等价物。
///
/// 成功返回 [`DHCP_OK`]，失败返回 Windows 的错误码。
pub fn renew_dhcp(nic_name: &str, mac: Option<&[u8]>) -> Result<u32, u32> {
    #[cfg(windows)]
    {
        let index = if_index_of(nic_name, mac).ok_or(DHCP_ERR_NOTFOUND)?;
        let code = unsafe { imp::renew(index, nic_name) };
        if code == 0 {
            Ok(DHCP_OK)
        } else {
            Err(code)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (nic_name, mac);
        Err(DHCP_ERR_IFINFO)
    }
}

/// 释放该网卡的 DHCP 租约 —— 官方认证流程内 `"Release IP wired"` 的等价物。
///
/// 释放后 IP 会退回 APIPA，**必须**紧接着调 [`renew_dhcp`] 让它重新握手。
pub fn release_dhcp(nic_name: &str, mac: Option<&[u8]>) -> Result<u32, u32> {
    #[cfg(windows)]
    {
        let index = if_index_of(nic_name, mac).ok_or(DHCP_ERR_NOTFOUND)?;
        let code = unsafe { imp::release(index, nic_name) };
        if code == 0 {
            Ok(DHCP_OK)
        } else {
            Err(code)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (nic_name, mac);
        Err(DHCP_ERR_IFINFO)
    }
}

/// 取该网卡当前的 `10.x` 地址（没有则 `None`）。
///
/// 刻意不依赖 `crate::net`：本模块保持自包含，才能被 `examples/dhcp_probe.rs`
/// 用 `#[path = "../src/dhcp.rs"]` 原样引入做实跑验证。
pub fn campus_ipv4(nic_name: &str) -> Option<Ipv4Addr> {
    pnet::datalink::interfaces()
        .into_iter()
        .find(|i| i.name == nic_name)
        .and_then(|iface| {
            iface.ips.iter().find_map(|ip| match ip.ip() {
                std::net::IpAddr::V4(v4) if v4.octets()[0] == 10 => Some(v4),
                _ => None,
            })
        })
}

/// 等该网卡拿到 `10.x` 租约，最多等 `timeout`。
pub fn wait_dhcp_ready(nic_name: &str, timeout: Duration) -> Option<Ipv4Addr> {
    let start = Instant::now();
    loop {
        if let Some(ip) = campus_ipv4(nic_name) {
            return Some(ip);
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
}

/// 官方等价物：`IpReleaseAddress()` + `IpRenewAddress()` —— 把租约彻底翻新。
///
/// 官方在认证流程内部走的就是这条路（`"Release IP wired"` → `InitDhcp`）。
/// 注意这会**短暂丢掉 IP**，所以只能在还没建立有效会话的阶段用。
pub fn recycle_dhcp(nic_name: &str, mac: Option<&[u8]>) -> Result<u32, u32> {
    // 先释放再续租 = 让 DHCP 完整重走 DISCOVER/OFFER/REQUEST
    let _ = release_dhcp(nic_name, mac);
    renew_dhcp(nic_name, mac)
}

/// 后台 DHCP 续租线程 —— 官方 `CDhcpThread`（继承 MFC `CWinThread`）的等价物。
///
/// 官方 `CDhcpThread` 的具体续租周期没有在反编译里直接暴露，这里按 DHCP 语义取
/// **30 分钟**：校园网 DHCP 租约通常是 2 小时，T1（50% 租期）= 1 小时，
/// 30 分钟续一次稳稳早于 T1，且续租报文本身也能维持 BRAS 侧的数据通路。
///
/// 这是一个**推断值**，不是从官方二进制里抄到的常量。
pub fn spawn_renewer(
    nic_name: String,
    mac: Option<[u8; 6]>,
    interval: Duration,
) -> Option<std::thread::JoinHandle<()>> {
    Some(std::thread::spawn(move || {
        loop {
            std::thread::sleep(interval);
            let mac_ref = mac.as_ref().map(|m| &m[..]);
            match renew_dhcp(&nic_name, mac_ref) {
                Ok(code) => log::info!("[DHCP] 主动续租完成 (code={})", code),
                Err(code) => {
                    // IpRenewAddress 需要管理员权限；官方客户端能续是因为它的
                    // SuService.exe 跑在 SYSTEM 服务里，而本项目是用户态程序，
                    // 结构上做不到。没有权限就别刷屏了 —— 停掉这个线程。
                    log::warn!(
                        "[DHCP] 主动续租失败 (code=0x{:X})，多半是缺少管理员权限；停用后台续租",
                        code
                    );
                    break;
                }
            }
        }
    }))
}
