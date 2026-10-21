use pcap::{Capture, Device};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: captest <device-name> [seconds]");
        std::process::exit(1);
    }
    let name = &args[1];
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(15);

    let devices = Device::list().expect("device list failed");
    let dev = devices
        .into_iter()
        .find(|d| d.name == *name)
        .expect("device not found");

    let mut cap = Capture::from_device(dev)
        .expect("from_device failed")
        .immediate_mode(true)
        .timeout(1000)
        .snaplen(2048)
        .open()
        .expect("open failed");

    println!("capturing on {} for {}s ...", name, secs);
    let start = std::time::Instant::now();
    let mut count: u64 = 0;
    let mut eapol: u64 = 0;
    while start.elapsed().as_secs() < secs {
        match cap.next_packet() {
            Ok(p) => {
                count += 1;
                let is_eapol =
                    p.data.len() > 14 && p.data[12] == 0x88 && p.data[13] == 0x8e;
                if is_eapol {
                    eapol += 1;
                }
                if count <= 5 || is_eapol {
                    println!(
                        "pkt#{} len={} eapol={} {:02x?}",
                        count,
                        p.header.len,
                        is_eapol,
                        &p.data[..p.data.len().min(24)]
                    );
                }
            }
            Err(e) => {
                // timeout expected each 1s
                let _ = e;
            }
        }
    }
    println!("TOTAL packets in {}s: {} (EAPOL: {})", secs, count, eapol);
}
