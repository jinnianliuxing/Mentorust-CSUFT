use clap_derive::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mentorust")]
#[command(about = "针对EAP协议锐捷校园网认证 - 三伏天秋不洛", version = "0.3.3", author = "fuqiuluo")]
pub struct EapArgs {
    /// 不带子命令直接运行 = 一键认证（内置本机配置，认证成功后窗口自动关闭）
    #[command(subcommand)]
    pub command: Option<EapCommands>,
}

#[derive(Subcommand)]
pub enum EapCommands {
    /// 校园网认证
    Auth {
        /// 网卡名称
        #[arg(short, long, default_value = "")]
        nic: String,

        /// dhcp模式 1(二次认证) 2(认证后) 3(认证前)
        #[arg(short, long, default_value_t = 0)]
        dhcp_mode: u8,

        /// 用户名
        #[arg(short, long)]
        username: String,

        /// 密码
        #[arg(short, long)]
        password: String,

        /// 是否后台运行
        #[arg(short, long, default_value_t = false)]
        background: bool,

        /// 反共享检测等级 0（关闭） 1（低） 2（中） 3（高）
        #[arg(short, long, default_value_t = 0)]
        anti_share: u8,
    },
    /// 解码配置文件
    DecodeConfig {
        /// 网卡名称
        #[arg(short, long)]
        path: String,
    },
    /// 自动抓包分析
    AutoCapture {
        /// 网卡名称(开启抓包器后请重走一遍认证流程)
        #[arg(short, long, default_value = "")]
        nic: String,
    },
    /// 打印所有Mac地址等信息
    PrintMac,
    /// 注销校园网认证（主动下线）
    Logoff {
        /// 网卡名称
        #[arg(short, long, default_value = "")]
        nic: String,
    },
    /// 诊断：只测 DHCP 续租，不发起认证、不会断网
    ///
    /// 用来确认 IpRenewAddress 是否真的能调通。认证前的 DHCP 分支只有在
    /// 网卡**没有** 10.x 租约时才会走到，机器已经在线时测不出来。
    DhcpTest {
        /// 网卡名称（留空 = 自动挑校园网有线口）
        #[arg(short, long, default_value = "")]
        nic: String,
        /// 加 `--release` 则先释放再续租（会短暂断网，慎用）
        #[arg(long, default_value_t = false)]
        release: bool,
    }
}
