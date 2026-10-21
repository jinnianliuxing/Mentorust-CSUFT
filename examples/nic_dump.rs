// Dump every NPF device with description / IPv4 / MAC so the GUI's NIC
// filter can be designed against real data instead of guesses.
//
// `pcap::Device` carries the human-readable description but no MAC;
// `pnet`'s `NetworkInterface` carries the MAC but no description.
// The two sets are joined on the NPF name (`\Device\NPF_{GUID}`).
use pcap::Device;
use pnet::datalink;

fn main() {
    let by_name: std::collections::HashMap<String, String> = datalink::interfaces()
        .into_iter()
        .filter_map(|i| {
            let mac = i.mac.map(|m| {
                format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m.0, m.1, m.2, m.3, m.4, m.5)
            })?;
            Some((i.name.clone(), mac))
        })
        .collect();

    match Device::list() {
        Ok(devs) => {
            for d in devs {
                println!("NAME  {}", d.name);
                println!("DESC  {}", d.desc.clone().unwrap_or_default());
                let ips: Vec<String> = d
                    .addresses
                    .iter()
                    .filter_map(|a| match a.addr {
                        std::net::IpAddr::V4(v) => Some(v.to_string()),
                        _ => None,
                    })
                    .collect();
                println!("IPV4  {}", ips.join(", "));
                println!(
                    "MAC   {}",
                    by_name.get(&d.name).cloned().unwrap_or_else(|| "-".into())
                );
                println!("----");
            }
        }
        Err(e) => println!("Device::list() failed: {}", e),
    }
}
