//! 网卡句柄的共享包装。
//!
//! 重要：libpcap 明确**不保证**同一个 `pcap_t *` 能被多线程并发使用
//! （见 pcap crate `capture/mod.rs` 的注释："it is not safe to Sync as
//! libpcap does not promise thread-safe access to the same `pcap_t *` from
//! multiple threads"）。原来的实现用 `UnsafeCell` + `unsafe impl Sync`
//! 绕过了这条约束，抓包线程与发包线程会同时在同一个句柄上操作，
//! 属于数据竞争 —— 这是"随机掉线/偶发异常"的隐患之一。
//!
//! 现在改为 `Mutex`：既得到真正互斥，也使句柄可以被安全替换
//! （网卡复位后重新打开）。

use std::sync::{Arc, Mutex, MutexGuard};
use pcap::{Active, Capture, Device};
use crate::eap::Status;
use crate::eap::Status::WaitingLoop;

pub struct SharedCapture {
    cap: Mutex<Capture<Active>>,
    status: Mutex<Status>,
    /// 记下设备信息，掉线时用于重开句柄
    dev: Mutex<Option<Device>>,
    mac: String,
}

impl SharedCapture {
    pub fn new(cap: Capture<Active>, dev: Device, mac: String) -> Arc<Self> {
        Arc::new(SharedCapture {
            cap: Mutex::new(cap),
            status: Mutex::new(WaitingLoop),
            dev: Mutex::new(Some(dev)),
            mac,
        })
    }

    /// 取网卡句柄锁。**只有抓包线程会用到它。**
    ///
    /// ⚠️ 不要再把发包逻辑挂到这把锁上：抓包线程在没有匹配包时会长时间阻塞在
    /// `for_each` 里（immediate mode + BPF 过滤下读超时不会让它返回），锁被长期
    /// 占用。发包走独立句柄，见 `spawn_packet_sender`。
    pub fn lock_cap(&self) -> MutexGuard<'_, Capture<Active>> {
        self.cap.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn status(&self) -> Status {
        *self.status.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_status(&self, status: Status) {
        *self.status.lock().unwrap_or_else(|e| e.into_inner()) = status;
    }

    /// 重新打开网卡句柄 —— 网卡复位 / 驱动异常导致收包失效时用它自愈。
    ///
    /// 用 `try_lock` 而不是阻塞锁：抓包线程在没有匹配包时会长时间阻塞在
    /// `for_each` 里并一直持有这把锁，用阻塞锁会把调用它的监督循环一起卡死
    /// （实测：日志停在"尝试重新打开网卡句柄..."之后再无任何输出）。
    /// 抢不到锁就放弃本次尝试，稍后重试即可。
    pub fn reopen(&self) -> Result<(), String> {
        let dev = {
            let g = self.dev.lock().unwrap_or_else(|e| e.into_inner());
            g.clone().ok_or_else(|| "未记录网卡信息".to_string())?
        };
        let cap = crate::open_pcap(dev, &self.mac).map_err(|e| format!("{:?}", e))?;
        match self.cap.try_lock() {
            Ok(mut g) => {
                *g = cap;
                Ok(())
            }
            Err(_) => Err("抓包线程仍持有网卡句柄，本次重开跳过".to_string()),
        }
    }
}
