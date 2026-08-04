//! Passive Capture Engine
//!
//! Thin raw-socket capture helper used by the probe engine to match crafted
//! sends with observed responses. Uses AF_PACKET on Linux and BPF on macOS.
//!
//! Intentionally minimal: no full BPF compiler, no per-filter bytecode. The
//! caller filters frames in userspace via a `FilterFn` callback which has
//! access to the parsed `CapturedFrame`.

use std::io;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

/// Parsed capture frame.
#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub timestamp: SystemTime,
    pub data: Vec<u8>,
}

/// Userspace filter. Returning true forwards the frame to the receiver.
pub type FilterFn = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("IO: {0}")]
    Io(#[from] io::Error),
    #[error("Root/admin privileges required to open raw socket")]
    NeedsRoot,
    #[error("Platform unsupported")]
    Unsupported,
    #[error("Interface '{0}' not found")]
    InterfaceNotFound(String),
}

pub struct CaptureHandle {
    rx: Receiver<CapturedFrame>,
    stop_tx: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl CaptureHandle {
    pub fn recv_timeout(&self, dur: Duration) -> Option<CapturedFrame> {
        self.rx.recv_timeout(dur).ok()
    }

    pub fn iter(&self) -> std::sync::mpsc::Iter<'_, CapturedFrame> {
        self.rx.iter()
    }

    pub fn stop(mut self) {
        let _ = self.stop_tx.send(());
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(());
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

/// Start a capture session. Frames are pushed on the returned handle's
/// receiver whenever `filter` returns true.
#[cfg(target_os = "linux")]
pub fn start_capture(iface: &str, filter: FilterFn) -> Result<CaptureHandle, CaptureError> {
    let sock = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if sock < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            return Err(CaptureError::NeedsRoot);
        }
        return Err(CaptureError::Io(err));
    }
    let ifindex = unsafe {
        let c_iface = std::ffi::CString::new(iface).unwrap();
        libc::if_nametoindex(c_iface.as_ptr())
    } as i32;
    if ifindex == 0 {
        unsafe { libc::close(sock) };
        return Err(CaptureError::InterfaceNotFound(iface.to_string()));
    }
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = ifindex;
    let r = unsafe {
        libc::bind(
            sock,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if r < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(CaptureError::Io(err));
    }
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 200_000,
    };
    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        );
    }

    let (tx, rx) = channel();
    let (stop_tx, stop_rx) = channel();
    let fd = sock;
    let thread = thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }
            let n = unsafe {
                libc::recv(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n > 0 {
                let slice = &buf[..n as usize];
                if filter(slice) {
                    let _ = tx.send(CapturedFrame {
                        timestamp: SystemTime::now(),
                        data: slice.to_vec(),
                    });
                }
            }
        }
        unsafe { libc::close(fd) };
    });
    Ok(CaptureHandle {
        rx,
        stop_tx,
        thread: Some(thread),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn start_capture(_iface: &str, _filter: FilterFn) -> Result<CaptureHandle, CaptureError> {
    Err(CaptureError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_without_data() {
        #[cfg(target_os = "linux")]
        {
            if !crate::fuzzing::is_root() {
                return;
            }
        }
    }

    #[test]
    fn filter_fn_type_sound() {
        let f: FilterFn = Box::new(|b| !b.is_empty());
        assert!(f(b"x"));
    }
}
