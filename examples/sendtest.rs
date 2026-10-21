use pcap::{Capture, Device};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// EAPOL-Start frame (same as mentorust build_hello_packet):
// dst(6) + src(6) + ethertype 0x888e(2) + version 0x01(1) + type 0x01(1) + length 0x0000(2)
fn build_hello_packet(dest_mac: &[u8], local_mac: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(18);
    packet.extend_from_slice(dest_mac);
    packet.extend_from_slice(local_mac);
    packet.extend_from_slice(&0x888e_u16.to_be_bytes());
    packet.push(0x01); // version 802.1X-2001
    packet.push(0x01); // type EAPOL-Start
    packet.extend_from_slice(&0x0000_u16.to_be_bytes());
    packet
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: sendtest <device-name> [seconds]");
        std::process::exit(1);
    }
    let name = args[1].clone();
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);

    let devices = Device::list().expect("device list failed");
    let dev = devices
        .into_iter()
        .find(|d| d.name == name)
        .expect("device not found");
    let local_mac = "b0:25:aa:5b:64:ef";

    let seen_outbound = Arc::new(AtomicU64::new(0));
    let seen_total = Arc::new(AtomicU64::new(0));
    let seen_eapol = Arc::new(AtomicU64::new(0));

    // capture thread: no filter, watch for our own EAPOL frames
    let (t_dev, t_out, t_total, t_eapol) =
        (dev.clone(), seen_outbound.clone(), seen_total.clone(), seen_eapol.clone());
    let h = std::thread::spawn(move || {
        let mut cap = Capture::from_device(t_dev)
            .unwrap()
            .immediate_mode(true)
            .timeout(500)
            .snaplen(2048)
            .open()
            .unwrap();
        let start = std::time::Instant::now();
        while start.elapsed().as_secs() < secs {
            if let Ok(p) = cap.next_packet() {
                t_total.fetch_add(1, Ordering::SeqCst);
                let data = &p.data[..p.data.len().min(6)];
                if data == [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03] {
                    t_eapol.fetch_add(1, Ordering::SeqCst);
                    println!("[cap] EAPOL-to-PAE frame, len={}, src={:02x?}", p.header.len, &p.data[6..12]);
                    if p.data[6..12] == [0xb0, 0x25, 0xaa, 0x5b, 0x64, 0xef] {
                        t_out.fetch_add(1, Ordering::SeqCst);
                        println!("[cap] >>> OUR OWN EAPOL frame looped back! send path WORKS");
                    }
                }
            }
        }
    });

    // send thread: send EAPOL Start every 2s
    let s_dev = dev;
    let sh = std::thread::spawn(move || {
        let mut cap = Capture::from_device(s_dev)
            .unwrap()
            .immediate_mode(true)
            .timeout(500)
            .open()
            .unwrap();
        let packet = build_hello_packet(
            &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x03],
            &[0xb0, 0x25, 0xaa, 0x5b, 0x64, 0xef],
        );
        let start = std::time::Instant::now();
        while start.elapsed().as_secs() < secs {
            match cap.sendpacket(packet.as_slice()) {
                Ok(_) => println!("[send] EAPOL Start sent ({} bytes)", packet.len()),
                Err(e) => println!("[send] ERROR: {}", e),
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    });

    sh.join().unwrap();
    h.join().unwrap();
    println!(
        "SUMMARY: captured_total={} eapol_frames={} our_frames_loopback={}",
        seen_total.load(Ordering::SeqCst),
        seen_eapol.load(Ordering::SeqCst),
        seen_outbound.load(Ordering::SeqCst)
    );
}
