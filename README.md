# Mentorust · CSUFT 校园网认证客户端

一个用 **Rust** 编写的锐捷（Ruijie）802.1X 有线校园网认证客户端，带**原生 Win32 图形界面**，
针对 **中南林业科技大学（CSUFT）** 有线校园网做了完整适配与稳定性加固。

> 本项目基于开源项目 [fuqiuluo/mentorust](https://github.com/fuqiuluo/mentorust) 二次开发：
> 在其 EAPOL / EAP-MD5 认证内核之上重写了 Windows 交互层，并修复了若干会造成
> **「概率性掉线」** 的缺陷。非官方项目，与学校及锐捷公司无关。

---

## 特性

| 能力 | 说明 |
| --- | --- |
| **小窗口 GUI** | 客户区仅 360×142 像素，状态与最新消息在底部一行依次显示，不占屏幕 |
| **无黑窗** | 编译为 GUI 子系统，断开 / 退出 / 结束残留进程都不再闪控制台黑框 |
| **网卡选择** | 下拉框**只列真正能用的网卡** —— 虚拟网卡 / WAN 微型端口 / 回环伪设备全部剔除，带 `10.x` 地址的（校园网网段）排在最前，无线排在有线之后 |
| **官方式 DHCP 管理** | 认证**之前**先确保网卡持有合法租约（对齐官方 `EnableBeforeAuth`）—— 这是「整 60 分钟准点掉线」的关键修复 |
| **掉线自愈** | 检测到真实掉线后自动「发 EAPOL-Logoff 清会话 → 重新认证」 |
| **开机自启 + 自动连接** | 可选；勾选「自动连接」需先启用「开机自启」，关闭自启则自动连接置灰 |
| **手动断开闩锁** | 点「断开」后**不会**自动连回来，只有再次点「连接」才恢复 |
| **无外部运行时依赖** | 静态单文件 exe，不需要 VC++ 运行库 / .NET / Python |
| **零配置留存** | 除同目录 `mentorust-gui.ini` 外不写任何注册表项（自启项除外，且可关闭） |
| **托盘常驻** | 点 X 只是收进托盘，认证进程照常保活；托盘右键可「显示 / 连接 / 断开 / 退出」，双击图标唤回窗口 |
| **口令不落明文** | 保存的密码用 Windows DPAPI 按**当前用户**加密（`pass_enc=`），配置文件被拷走也解不开；后台进程的口令走匿名管道，进程命令行里看不到 |
| **诊断日志** | `%LOCALAPPDATA%\mentorust\logs\mentorust-日期-角色.log`，毫秒时间戳、按天分文件、30 天自动清理；带 `[EVT:SESSION_BEGIN]` / `[EVT:DROP]` 等结构化事件，可直接交给脚本做离线分析 |

---

## 快速开始（Windows · 免编译）

**[前往 Releases 下载](https://github.com/jinnianliuxing/Mentorust-CSUFT/releases/latest)** —— 仓库内也留了一份，路径为 `dist/Mentorust-CSUFT-portable.zip`。

1. 解压，**全部文件解压到同一文件夹**。
2. 双击 `run.bat` —— 它会**自动检查 Npcap**：
   装了就跳过；没装则打开 <https://npcap.com/#download> 引导你安装。
3. 窗口里填写校园网账号 / 密码，选有线网卡，点「连接」。

> **首次连接时若提示没找到网卡**，请展开下拉框手动选那张带 `10.x` 地址的网卡。
> 想要桌面快捷方式的话：右键 `mentorust.exe` → 发送到 → 桌面快捷方式。

### 关于 Npcap（必需）

Mentorust 靠 Npcap 收发 802.1X 认证帧，**没有它无法工作**。
安装时务必勾选 **`Install Npcap in WinPcap API-compatible Mode`**。

> ⚠️ **本仓库不附带 Npcap 安装器**。Npcap 免费版许可明确写着
> “may be used but **not externally redistributed**”（可使用，但不得对外再分发），
> 只有付费 OEM 版才允许随产品分发。所以这里只提供官网链接，请自行下载安装。

---

## 从源码编译

### 前置条件

- Rust 工具链（stable，建议 1.75+）
- **Npcap SDK**（编译期需要 `wpcap.lib` / `Packet.lib`）
- MinGW-w64（用于链接，或使用 MSVC 工具链）

### 构建命令

```bash
# 1. 安装 Npcap 运行时 + 下载 Npcap SDK
#    将 SDK 解压到本地，例如 D:/npcap-sdk

# 2. 指定 lib 目录后编译（Windows / bash 环境）
export LIBPCAP_LIBDIR="D:/npcap-sdk/Lib/x64"
cargo build --release
```

产物位于 `target/release/mentorust.exe`。

> `Cargo.toml` 里通过 `[patch.crates-io]` 把 `pcap` 指向仓库内的 `pcap/` 子目录：
> 这是为了让 libpcap 的错误信息在**中文 Windows** 下正确解码（见下文「实现要点」），
> 因此 **`pcap/` 目录必须随源码一起保留**。

### 命令行用法

```bash
mentorust auth -u 用户名 -p 密码        # 前台认证
mentorust auth -u 用户名 -p 密码 -b     # 后台运行（Windows）
mentorust logoff                        # 发送 EAPOL-Logoff 主动下线
mentorust print-mac                     # 列出本机网卡名称与 MAC
```

环境变量：`RUST_LOG`（日志级别）、`EAPOL_ENABLE_DHCP`、`MENTORUST_MAX_RETRIES` 等，详见上游说明。

---

## 实现要点

### 1. 心跳必须真的发出去

认证成功后的保活心跳（锐捷私有 EAPOL `0xBF`）原实现被「在线判定」门控，
而心跳周期与「认证稳定期」恰好都等于 20 秒 —— 结果是**一帧心跳都发不出去**，
会话不续期，交换机侧超时后踢人。现在心跳与探测解耦：只要处于已授权状态就无条件周期发送，
并在认证成功瞬间补发一帧。

### 2. 掉线要发 Logoff，否则会卡死在坏会话上

掉线后若只重复发 `EAPOL-Start` 重新认证，BRAS 上那条「半开」的旧会话不会被清理，
表现是 **认证成功、但数据包被全部丢弃** 的死循环。
现在每次重认证前先发 `EAPOL-Logoff` 清理旧会话。

### 3. 判定要钝一点，别自己把自己抖死

认证成功后 DHCP / NAT 未必立刻就绪，此时主动探测必然假失败；
原先「5 秒一次 × 3 次失败即强制重认证」会在认证窗口期自激抖动。
现在：真实可达性判定放宽到约 30 秒阈值，且认证成功后设有稳定期。

### 4. libpcap 的中文错误信息不再被吞掉

仓库内 `pcap/` 对上游 crate 打了一个补丁：`cstr_to_string()` 在 UTF-8 解码失败时
回落到 **GBK**。中文 Windows 下 libpcap / Npcap 的错误串是 GBK 编码，原实现会直接
退化成 `invalid UTF-8`，导致真实的失败原因（设备未就绪 / 权限不足 …）永远看不到。

### 5. 心跳要带递增序号，BRAS 才认

锐捷的心跳帧里藏着一个 `echo_key` 种子（从认证成功的报文 `0x1c + frame[0x1b] + 0x69 + 24`
处取出 4 字节）。原实现每帧都塞同一个常量，BRAS 判定为「重放」直接丢弃 —— 表现为
**每小时准点被踢下线**（实测会话寿命 3612 s ± 数秒，三次一致）。

现在按 MentoHUST 的算法逐帧写入 `encode(seed + seq)` 与 `encode(seq)`，`seq` 从 `0x102B`
起严格递增；实测连续在线 74.7 分钟、225 帧序号无跳变、0 次重认证。

### 6. 托盘常驻，关窗口 ≠ 断网

窗口只负责「看得见」，真正保活的是 `--ghost` 后台进程。点 X 只是把窗口藏起来
（`WM_CLOSE` → `ShowWindow(SW_HIDE)`），托盘图标仍在、认证照常。
只有托盘右键「退出」才走完整收尾：先发 `EAPOL-Logoff` 注销会话，再结束后台进程 ——
否则会在 BRAS 侧留下半开会话，下次要等超时才连得上。

### 7. 口令不再出现在三个地方

原先口令会以三种形式落地：进程命令行（`--gui-pass "..."`）、明文 ini（`pass=...`）、
以及 GUI 进程内存里的常驻副本。现在：

- **命令行**：改为匿名管道传递（`CreatePipe` + 继承句柄 + `--cred-stdin`），
  同用户权限下枚举 `Win32_Process.CommandLine` 只会看到 `--ghost --gui-nic "..." --cred-stdin`；
- **配置文件**：只写 `pass_enc=<DPAPI 密文>`，DPAPI 绑定当前 Windows 用户，
  换机器 / 换账户都解不开；升级后首次启动会自动把旧明文就地改写；
- **兼容**：`--gui-pass` 的回落分支已移除，代码里不再有「明文口令进命令行」的路径。

---

### 8. 认证之前先拿到 IP（官方式 DHCP 管理）

实测（2026-10-20/21）：**认证时网卡处于 APIPA(169.254.x.x) 建立的会话，会被 BRAS
在 3600 s 准点踢掉**；而建立时已经持有 `10.x` 的会话能活 87~207 分钟。

官方客户端的对策是 `[DHCPMODE] EnableBeforeAuth=1` —— **认证之前就启动 DHCP**，
让 EAPOL 握手发生在一个已经持有合法租约的状态上。本项目自己实现 EAPOL 握手
（不经过 Windows 的 802.1X 引擎），EAP 响应帧用网卡 IPv4 作源 IP —— 带着 APIPA
去认证既会发出源地址非法的帧，也会把会话建立成那种短命的，所以官方这套 DHCP
管理必须照搬。

实现见 `src/dhcp.rs`：`IpRenewAddress` / `IpReleaseAddress` 的封装，
以及认证前的 `wait_dhcp_ready()`。

> ⚠️ `IpRenewAddress` / `IpReleaseAddress` 需要管理员权限。官方客户端能调通是因为
> 它的 `SuService.exe` 跑在 SYSTEM 服务里；本项目是用户态程序，结构上做不到。
> 此时降级为「等系统 DHCP 客户端自己续租」（T1 时刻它会照常工作），不影响功能。

### 9. 手动断开要真的断开

点「断开」/ 托盘「退出」时，除了发 EAPOL-Logoff 注销服务器侧会话，还要
**释放 DHCP 租约**，否则机器上仍留着一个 `10.x` 地址和一份有效租约，
而校园网会话已经没了 —— 那不算干净。

同时注意：`release` 版是 `panic = 'abort'`，**pcap 的 `Capture` 在句柄失效时
`Drop` 会 panic**，进程会被静默杀掉（无 unwinding、无 panic 消息、后续日志全丢）。
所以退出流程里**不能**显式 `drop(cap)`，让句柄在函数返回时自然释放。

---

## 目录结构

```
.
├── Cargo.toml / Cargo.lock     # 工程与依赖锁定
├── LICENSE                     # MIT（上游版权声明保留）
├── src/
│   ├── main.rs                 # 程序入口、认证主循环、进程管理
│   ├── gui.rs                  # Win32 图形界面
│   ├── net.rs                  # 网卡地址与在线探测
│   ├── config.rs               # mentorust-gui.ini 读写
│   ├── pcapx.rs                # 抓包句柄封装
│   ├── eap/                    # EAP / EAPOL 状态机
│   └── packets/                # EAPOL / 锐捷私有帧构造
├── pcap/                       # 打过补丁的 pcap crate（必须保留）
└── dist/                       # 预编译产物
    ├── mentorust.exe           # 脱敏主程序（打包时复制进便携包）
    ├── Mentorust-CSUFT-portable.zip                # 便携包（对外发布）
    └── portable/               # 便携包内容源
        ├── run.bat             # 启动器：自动检测 Npcap（纯 ASCII，避免 cmd 乱码）
        └── README.txt          # 中文说明（UTF-8 带 BOM）
```

---

## 免责声明

- 本项目仅供**学习与个人研究**使用，请遵守学校网络管理规定。
- 使用本软件所产生的一切后果由使用者自行承担。
- 请勿将本软件用于任何商业用途或违反法律法规的场景。

## 许可

[MIT](LICENSE)。上游版权归原作者（伏秋洛）所有；`pcap/` 子目录遵循其自身的 MIT / Apache-2.0 双许可。
