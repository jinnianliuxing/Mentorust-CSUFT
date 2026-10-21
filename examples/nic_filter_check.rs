// Verify the GUI's NIC filter against the real device list.
//
// Re-implements the same rules as `gui.rs::scan_nics` so the outcome can
// be inspected without opening the GUI. If the rules in gui.rs change,
// this must be updated in lockstep.
use pcap::Device;

const VIRTUAL_NIC_HINTS: [&str; 12] = [
    "Virtual", "Miniport", "loopback", "Loopback", "Tunnel", "TAP", "Tap",
    "Bluetooth", "Npcap", "NPCAP", "Filter", "Hyper-V",
];

fn is_virtual_nic(desc: &str) -> bool {
    VIRTUAL_NIC_HINTS.iter().any(|h| desc.contains(h))
}

fn is_wireless_nic(desc: &str) -> bool {
    let d = desc.to_ascii_lowercase();
    d.contains("wi-fi") || d.contains("wifi") || d.contains("wireless")
        || d.contains("wlan") || d.contains("802.11")
}

fn addr_unusable(ip: &std::net::Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()
        || ip.octets()[0] == 169 && ip.octets()[1] == 254
}

fn main() {
    let mut rows: Vec<(u8, String, String)> = Vec::new();
    let mut dropped: Vec<String> = Vec::new();

    match Device::list() {
        Ok(devs) => {
            for d in devs {
                let base = d.desc.clone().unwrap_or_else(|| d.name.clone());
                if is_virtual_nic(&base) {
                    dropped.push(base);
                    continue;
                }
                let v4 = d.addresses.iter().find_map(|a| match a.addr {
                    std::net::IpAddr::V4(v) => Some(v),
                    _ => None,
                });
                let usable = v4.filter(|ip| !addr_unusable(ip));
                let wireless = is_wireless_nic(&base);
                let base_rank = if wireless { 3u8 } else { 0u8 };
                let (rank, label) = match usable {
                    Some(ip) if ip.octets()[0] == 10 => {
                        (base_rank, format!("{} · {}", base, ip))
                    }
                    Some(ip) => (base_rank + 1, format!("{} · {}", base, ip)),
                    None => (base_rank + 2, format!("{} · 无地址", base)),
                };
                rows.push((rank, d.name.clone(), label));
            }
        }
        Err(e) => {
            println!("Device::list() failed: {}", e);
            return;
        }
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.2.cmp(&b.2)));

    println!("=== DROPPED ({} items) ===", dropped.len());
    for d in &dropped {
        println!("  x  {}", d);
    }
    println!();
    println!("=== SHOWN IN DROPDOWN ({} items) ===", rows.len());
    for (rank, _name, label) in &rows {
        println!("  {}  [rank {}]  {}", if *rank <= 2 { "+" } else { " " }, rank, label);
    }
    println!();
    println!("(rank 0-2 = wired, 3-5 = wireless; default selection = first row)");
}
