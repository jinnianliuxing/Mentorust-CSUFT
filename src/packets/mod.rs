mod rtv;

use std::process::exit;
use bytes::{BufMut, Bytes, BytesMut};
use log::info;
use pnet::datalink::NetworkInterface;
use crate::eap::{CODE_RESPONSE, EAP_TYPE_IDENTITY, EAP_TYPE_MD5_CHALLENGE};
use crate::eap::utils::{check_sum, encrypt_rtv};

const VERSION_8021X_2001: u8 = 0x1;
const VERSION_8021X_2004: u8 = 0x2;
const VERSION_8021X_2010: u8 = 0x3;

const ETH_P_PAE: u16 = 0x888e;

/// 承载的是EAP消息
const TYPE_EAP_PACKET: u8 = 0x0;
/// 发起认证
const TYPE_EAPOL_START: u8 = 0x1;
/// 下线
const TYPE_EAPOL_LOGOFF: u8 = 0x2;
/// 交换密钥
const TYPE_EAPOL_KEY: u8 = 0x3;
/// EAPOL-ASF-ALERT
const TYPE_EAPOL_ASF_ALERT: u8 = 0x4;
/// HELLO
const TYPE_EAPOL_HEARTBEAT: u8 = 0xbf;

/// 寻找认证服务器
pub fn build_hello_packet(
    dest_mac: &[u8],
    local_mac: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(16 + 2);
    packet.extend_from_slice(&build_eap(dest_mac, local_mac, ETH_P_PAE, VERSION_8021X_2001, TYPE_EAPOL_START));
    packet.extend_from_slice(&0x0000_i16.to_be_bytes()); // length
    packet
}

/// 主动下线（EAPOL-Logoff，type 0x02）。
///
/// 用途：**清理 BRAS/交换机上的旧会话**。掉线后只发 EAPOL-Start 是清不掉
/// 卡住的半开会话的 —— 会死锁在"认证成功但数据面被丢弃"的循环里；
/// 用户手动「断开」（发 Logoff）再「连接」却能立刻恢复。重认证前补这一步，
/// 等价于自动复刻该操作。
pub fn build_logoff_packet(
    dest_mac: &[u8],
    local_mac: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(16 + 2);
    packet.extend_from_slice(&build_eap(dest_mac, local_mac, ETH_P_PAE, VERSION_8021X_2001, TYPE_EAPOL_LOGOFF));
    packet.extend_from_slice(&0x0000_i16.to_be_bytes()); // length
    packet
}

/// 发送用户名
pub fn build_identity_packet(
    dest_mac: &[u8],
    local_mac: &[u8],
    ipv4: &[u8],
    ipv6: &[u8],
    identity: &str,
    id: u8
) -> Vec<u8> {
    let eap_len = (identity.len() + 5) as u16; // 锐捷
    let mut packet = BytesMut::new();
    packet.extend_from_slice(&build_eap(dest_mac, local_mac, ETH_P_PAE, VERSION_8021X_2001, TYPE_EAP_PACKET)); // 16
    packet.put_u16(eap_len);
    packet.put_u8(CODE_RESPONSE); // eap code
    packet.put_u8(id); // eap id
    packet.put_u16(eap_len); // eap len
    packet.put_u8(EAP_TYPE_IDENTITY); // eap type
    packet.put_slice(identity.as_bytes()); // eap identity
    packet.put(build_ruijie_private_extended_data(local_mac, ipv4, ipv6));

    packet.to_vec()
}

/// 发送密码
pub fn build_password_packet(
    dest_mac: &[u8],
    local_mac: &[u8],
    ipv4: &[u8],
    ipv6: &[u8],
    identity: &str,
    password: &str,
    id: u8,
    seed: &[u8]
) -> Vec<u8> {
    let eap_len = (identity.len() + 22) as u16; // 锐捷
    let mut packet = BytesMut::new();
    packet.extend_from_slice(&build_eap(dest_mac, local_mac, ETH_P_PAE, VERSION_8021X_2001, TYPE_EAP_PACKET)); // 16
    packet.put_u16(eap_len);
    packet.put_u8(CODE_RESPONSE); // eap code
    packet.put_u8(id); // eap id
    packet.put_u16(eap_len); // eap len
    packet.put_u8(EAP_TYPE_MD5_CHALLENGE); // eap type

    packet.put_u8(0x10); // password md5 length
    let mut md5_pwd = BytesMut::with_capacity(password.len() + seed.len() + 1);
    md5_pwd.put_u8(id);
    md5_pwd.put_slice(password.as_bytes());
    md5_pwd.put_slice(seed);
    let md5_pwd = md5::compute(md5_pwd.as_ref()).0;
    if option_env!("MENTORUST_DEBUG") == Some("1") {
        info!("PasswordMD5: {}", hex::encode(&md5_pwd));
    }
    packet.put_slice(&md5_pwd);
    packet.put_slice(identity.as_bytes()); // eap identity
    packet.put(build_ruijie_private_extended_data(local_mac, ipv4, ipv6));

    packet.to_vec()
}

/// 锐捷私有混淆：把一个字节的 8 位颠倒，再按位取反。
///
/// 逐字对应 MentoHUST `myfunc.c` 的 `encode()`。心跳的种子与序号都靠它
/// 混淆；少这一步，BRAS 认不出心跳，会话满 3600 秒被清 -> 每 60 分钟掉线。
pub fn encode_byte(mut base: u8) -> u8 {
    let mut result: u8 = 0;
    for _ in 0..8 {
        result <<= 1;
        result |= base & 0x01;
        base >>= 1;
    }
    !result
}

/// 心跳（EAPOL 0xBF）状态机。
///
/// 锐捷心跳不是固定报文：认证成功包里带一个 4 字节种子，之后每发一帧把
/// 序号 +1，再把 `种子+序号` 与 `序号` 各自 encode 后回填到整帧偏移
/// 0x18 与 0x22。对应 MentoHUST 的 `getEchoKey()` / `fillEchoPacket()`。
pub struct EchoState {
    key: u32,
    no: u32,
}

impl EchoState {
    /// `no` 的初值与 MentoHUST `fillMd5Packet()` 一致。
    pub fn new(key: u32) -> Self {
        Self { key, no: 0x0000_102B }
    }

    pub fn key(&self) -> u32 {
        self.key
    }

    /// 把当前这一帧的 echo 数据写进整帧缓冲，然后序号自增。
    ///
    /// `frame` 是含以太网头的完整帧，所以 0x18 / 0x22 可以直接当下标用。
    pub fn fill(&mut self, frame: &mut [u8]) {
        if frame.len() >= 0x26 {
            let sum = self.key.wrapping_add(self.no);
            let no = self.no;
            for i in 0..4 {
                let shift = 24 - 8 * i;
                frame[0x18 + i] = encode_byte((sum >> shift) as u8);
                frame[0x22 + i] = encode_byte((no >> shift) as u8);
            }
        }
        self.no = self.no.wrapping_add(1);
    }
}

/// 从认证成功包（整帧，含以太网头）里取出心跳种子。
///
/// 偏移公式来自 MentoHUST `getEchoKey()`：`0x1c + frame[0x1b] + 0x69 + 24`。
/// 取到 4 字节后逐字节 encode，再当作大端整数 —— 这是原作在小端机上的
/// 实际语义（值先按小端读、字节反转，再对内存字节逐个 encode），必须原样
/// 复刻，否则算出的 `种子+序号` 对不上。
pub fn extract_echo_key(frame: &[u8]) -> Option<u32> {
    if frame.len() <= 0x1b {
        return None
    }
    let offset = 0x1c + frame[0x1b] as usize + 0x69 + 24;
    if offset + 4 > frame.len() {
        return None
    }
    let raw = &frame[offset..offset + 4];
    let key = u32::from_be_bytes([
        encode_byte(raw[0]),
        encode_byte(raw[1]),
        encode_byte(raw[2]),
        encode_byte(raw[3]),
    ]);
    // 全 0 / 全 1 = 取到的是空白区，不是真种子
    if key == 0 || key == u32::MAX {
        return None
    }
    Some(key)
}

/// 心跳包
pub fn build_heartbeat_packet(
    dest_mac: &[u8],
    local_mac: &[u8],
    echo: Option<&mut EchoState>,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(16 + 2 + 30);
    packet.extend_from_slice(&build_eap(dest_mac, local_mac, ETH_P_PAE, VERSION_8021X_2001, TYPE_EAPOL_HEARTBEAT));

    // 模板取自 MentoHUST sendEchoPacket()：偏移 0x18 / 0x22 两处 4 字节是
    // 变化位，下面会被 EchoState::fill() 改写。这里的初值只在拿不到种子
    // （回退路径）时生效，所以填的是原厂模板的占位值。
    const ECHO_DATA: [u8; 30] = [
        0xFF,0xFF,0x37,0x77,0x7F,0x9F,0xFF,0xFF,0xD9,0x13,0xFF,0xFF,0x37,0x77,0x7F,
        0x9F,0xFF,0xFF,0xF7,0x2B,0xFF,0xFF,0x37,0x77,0x7F,0x3F,0xFF,0x00,0x00,0x00
    ];
    packet.put_u16(0x1e);
    packet.extend_from_slice(&ECHO_DATA);

    if let Some(state) = echo {
        state.fill(&mut packet);
    }

    packet
}

pub(crate) fn build_ruijie_private_extended_data(
    local_mac: &[u8],
    ipv4: &[u8],
    ipv6: &[u8],
) -> Bytes {
    let mut pkt = BytesMut::new();

    pkt.extend_from_slice(rtv::rtv_net_config(ipv4).as_slice());
    pkt.put(rtv::rtv_process_name());
    pkt.put(rtv::rtv_empty());
    pkt.put(rtv::rtv_random_string());
    pkt.put(rtv::rtv_dhcp_flag());
    pkt.put(rtv::rtv_mac(local_mac));
    pkt.put(rtv::rtv_v4_hash());
    pkt.put(rtv::rtv_ipv6_count());
    pkt.put(rtv::rtv_ll_ipv6());
    pkt.put(rtv::rtv_ll_ipv6_t(ipv6));
    pkt.put(rtv::rtv_global_ipv6());
    pkt.put(rtv::rtv_v3_hash());
    pkt.put(rtv::rtv_service());
    pkt.put(rtv::rtv_hdd_ser());
    pkt.put(rtv::rtv_rj_ver());
    pkt.put(rtv::rtv_dsmscl_exits());
    pkt.put(rtv::rtv_os_bits());
    pkt.put(rtv::rtv_client_ver());
    pkt.put(rtv::rtv_unk_1());
    pkt.put(rtv::rtv_dns());

    pkt.freeze()
}

/// 构建eapol包头
pub fn build_eap(
    dest_mac: &[u8],
    local_mac: &[u8],
    proto: u16,
    ver: u8,
    typ: u8,
) -> Vec<u8> {
    let mut head = Vec::with_capacity(12 + 2 + 2);
    head.extend_from_slice(dest_mac);
    head.extend_from_slice(local_mac);
    head.extend_from_slice(&proto.to_be_bytes());
    head.extend_from_slice(&ver.to_be_bytes());
    head.extend_from_slice(&typ.to_be_bytes());
    head // 6+6+2+1+1=16
}

#[test]
fn test_pwd_md5() {
}