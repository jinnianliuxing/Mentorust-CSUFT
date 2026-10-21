//! 只发送 EAPOL-Logoff（注销下线），**不结束任何进程**。
//!
//! 与 `mentorust.exe logoff` 的区别：logoff 会先 taskkill 掉后台认证进程，
//! 而这个工具不动进程。用它可以把端口踢成"未授权"状态，同时让后台认证进程
//! 继续存活 —— 正好用来验证「掉线后自动重新认证」这条链路。
//!
//! 用法: logoffonly [nic] [mac]

use pcap::{Capture, Device};

const NIC: &str = r"\Device\NPF_{36CE47E8-9BE8-4F74-AF8D-FAB2027BC2AE}";
const MAC: &str = "b0:25:aa:5b:64:ef";

fn main() {
    let nic = std::env::args().nth(1).unwrap_or_else(|| NIC.to_string());
    let mac_s = std::env::args().nth(2).unwrap_or_else(|| MAC.to_string());

    let dev = Device::list()
        .expect("枚举网卡失败")
        .into_iter()
        .find(|d| d.name == nic)
        .expect("未找到指定网卡");

    let mut local = [0u8; 6];
    hex::decode_to_slice(mac_s.replace(":", ""), &mut local).expect("MAC 解析失败");

    let mut cap = Capture::from_device(dev)
        .expect("打开网卡失败")
        .immediate_mode(true)
        .timeout(1000)
        .open()
        .expect("打开抓包句柄失败（Npcap 装了吗？）");

    for dest in [
        [0x01u8, 0x80, 0xc2, 0x00, 0x00, 0x03],
        [0x01, 0xd0, 0xf9, 0x00, 0x00, 0x03],
    ] {
        let mut f = Vec::with_capacity(18);
        f.extend_from_slice(&dest);
        f.extend_from_slice(&local);
        f.extend_from_slice(&0x888e_u16.to_be_bytes());
        f.push(0x01); // 802.1X-2001
        f.push(0x02); // EAPOL-Logoff
        f.extend_from_slice(&0x0000_u16.to_be_bytes());
        match cap.sendpacket(f.as_slice()) {
            Ok(_) => println!("已向 {:02x?} 发送 EAPOL-Logoff", dest),
            Err(e) => println!("发送失败: {}", e),
        }
    }
    println!("[LOGOFF-ONLY] 注销包已发送；本工具未结束任何进程。");
}
