
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Status {
    /// 等待pcap启动
    WaitingLoop,
    /// 开始认证
    StartAuth {
        dest_mac: [u8; 6]
    },
    /// 请求用户名
    EapRequestIdentity {
        dest_mac: [u8; 6],
        ipv4: [u8; 4],
        ipv6: [u8; 16],
        id : u8,
    },
    /// 验证密码
    EapRequestPassword {
        dest_mac: [u8; 6],
        ipv4: [u8; 4],
        ipv6: [u8; 16],
        id : u8,
        seed: [u8; 128],
        seed_len: u8,
    },
    /// 认证成功
    ///
    /// `echo_key` 是从成功包锐捷私有扩展里解出的心跳种子（已按锐捷算法
    /// encode 混淆）。`None` = 包结构对不上或偏移越界，心跳只能退回固定模板。
    AuthSuccess {
        dest_mac: [u8; 6],
        echo_key: Option<u32>,
    },
    /// 重新连接
    Reconnect,
    /// 下线
    Logoff,
    /// 心跳
    Heartbeat {
        dest_mac: [u8; 6],
    },
    /// 掉线后重新发起认证（发送 EAPOL-Start）。
    ///
    /// 与 `StartAuth` 的区别：它表示"这是一次重连尝试"，而不是用户主动点的
    /// 初次认证。**现在会写进 `sc.status()`** —— `start_loop` 用 `sc.status()`
    /// 判断失败包的含义；以前失败会让进程 `exit()`，所以不敢记；现在失败一律
    /// 转成 `AuthFailed` 交给监督循环退避重试，记录它是安全的，而且必须记：
    /// 否则"重连途中收到失败包"会被误判成"被踢下线"，进入没有退避的紧凑重试。
    ProbeStartAuth {
        dest_mac: [u8; 6]
    },
    /// 认证被服务器拒绝 / 重试失败事件。
    ///
    /// 取代原先直接 `exit(1/2/3)`：release 是 panic='abort'，进程一死单实例锁
    /// 还会残留（表现为"必须先断开才能连接"）。现在只把失败原因带回监督循环，
    /// 由它按 MentoHUST `-r` 的语义退避重试。
    AuthFailed {
        reason: &'static str,
    }
}