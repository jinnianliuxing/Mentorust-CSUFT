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
| **网卡选择** | 下拉框列出本机全部网卡，自动把带 `10.x` 地址的（校园网网段）排在前面 |
| **掉线自愈** | 检测到真实掉线后自动「发 EAPOL-Logoff 清会话 → 重新认证」 |
| **开机自启 + 自动连接** | 可选；勾选「自动连接」需先启用「开机自启」，关闭自启则自动连接置灰 |
| **手动断开闩锁** | 点「断开」后**不会**自动连回来，只有再次点「连接」才恢复 |
| **无外部运行时依赖** | 静态单文件 exe，不需要 VC++ 运行库 / .NET / Python |
| **零配置留存** | 除同目录 `mentorust-gui.ini` 外不写任何注册表项（自启项除外，且可关闭） |

---

## 快速开始（Windows · 免编译）

两种包任选其一，**都用同一个 `mentorust.exe`**：

| 包 | 特点 | 适合 |
| --- | --- | --- |
| `dist/Mentorust-CSUFT-portable.zip` | **便携版**，解压即用、配置只写在同目录（Npcap 仍需装一次） | 放 U 盘 / 任意文件夹 |
| `dist/Mentorust-CSUFT-v0.1.0-win64.zip` | **安装版**，装到 `%LOCALAPPDATA%` 并建桌面快捷方式 | 固定一台电脑长期用 |

**便携版（推荐）**

1. 解压 `dist/Mentorust-CSUFT-portable.zip`，**全部文件解压到同一文件夹**。
2. 双击 `run.bat` —— 它会**自动检查 Npcap**：
   装了就跳过；没装则打开 <https://npcap.com/#download> 引导你安装。
3. 窗口里填写校园网账号 / 密码，选有线网卡，点「连接」。

**安装版**

1. 解压 `dist/Mentorust-CSUFT-v0.1.0-win64.zip`。
2. 先装 Npcap（见下），再双击 `install.bat`。
3. 从桌面快捷方式启动，填账号密码，点「连接」。

> **首次连接时若提示没找到网卡**，请展开下拉框手动选那张带 `10.x` 地址的网卡。

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
    ├── mentorust.exe           # 脱敏主程序（两个包共用）
    ├── install.bat / uninstall.bat / README.txt    # 安装版脚本
    ├── Mentorust-CSUFT-v0.1.0-win64.zip            # 安装版包
    ├── Mentorust-CSUFT-portable.zip                # 便携版包
    └── portable/               # 便携版脚本源
        ├── run.bat             # 启动器：自动检测 Npcap（纯 ASCII，避免 cmd 乱码）
        └── README.txt          # 便携版中文说明（UTF-8 带 BOM）
```

---

## 免责声明

- 本项目仅供**学习与个人研究**使用，请遵守学校网络管理规定。
- 使用本软件所产生的一切后果由使用者自行承担。
- 请勿将本软件用于任何商业用途或违反法律法规的场景。

## 许可

[MIT](LICENSE)。上游版权归原作者（伏秋洛）所有；`pcap/` 子目录遵循其自身的 MIT / Apache-2.0 双许可。
