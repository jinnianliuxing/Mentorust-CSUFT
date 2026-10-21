use datalink::NetworkInterface;
use pnet::datalink;

pub(crate) fn print_all_network_mac() {
    let interfaces = datalink::interfaces();

    for interface in interfaces {
        if let Some(mac) = interface.mac {
            println!("Interface: {} MAC Address: {}", interface.name, mac);
        } else {
            println!("Interface: {} has no MAC address.", interface.name);
        }
        println!("  IP addresses: {:?}", interface.ips);

    }
}

pub(crate) fn get_network_interface_by_name(name: &str) -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();

    interfaces.iter().find(|dev| dev.name == name).cloned()
}

/// 按 MAC 地址找接口 —— **唯一稳定的标识**。
///
/// Windows 上 pnet 给的网卡名是 `\\Device\\NPF_{GUID}`，而这个 GUID
/// 会随网卡重新枚举而变化（实测有线口 ifIndex 7->8，GUID 也跟着变）。
/// 名字对不上时必须靠 MAC 兜底，否则在线判定会永远失败，
/// 30 分钟后开始每 30 秒误报一次掉线。
pub(crate) fn get_network_interface_by_mac(mac: &[u8; 6]) -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    interfaces
        .iter()
        .find(|dev| {
            // pnet 的 MacAddr 是 6 个 u8 的元组结构体，不是 slice。
            dev.mac
                .map(|m| m.0 == mac[0] && m.1 == mac[1] && m.2 == mac[2]
                    && m.3 == mac[3] && m.4 == mac[4] && m.5 == mac[5])
                .unwrap_or(false)
        })
        .cloned()
}


#[test]
fn test_get_dns() {
    print_all_network_mac()
}