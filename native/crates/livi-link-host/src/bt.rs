// SPDX-FileCopyrightText: 2025-2026 Lasse Heitgres
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use livi_net::tunnel::{self, PACKET_MAX};

use crate::link;

mod external;
pub mod trial;

const VHCI: &str = "/dev/vhci";
const RFKILL: &str = "/sys/class/rfkill";
const VENDOR_PKT: u8 = 0xff;
const CREATE_PRIMARY: [u8; 2] = [VENDOR_PKT, 0x00];
const POLL_MS: i32 = 200;
const RETRY: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const GIVE_UP: Duration = Duration::from_secs(3);

pub fn attach(
    on_adapter: impl Fn(u16) + Send + Sync + 'static,
    on_lost: impl Fn() + Send + 'static,
) {
    std::thread::spawn(move || {
        loop {
            match tunnel(&on_adapter) {
                Ok(true) => on_lost(),
                Ok(false) | Err(TunnelError::NoDongle(_)) => {}
                Err(e) => eprintln!("[bt] {e}"),
            }
            std::thread::sleep(RETRY);
        }
    });
}

/// Attach an existing stock controller through its local ADB TCP forward.
/// Pairing uses the host's own fresh bond store; controller-stored keys and
/// vendor command interfaces are deliberately unavailable through this proxy.
///
/// This worker is process-scoped, matching `attach`. The Linux helper calls it
/// once from `bluez::serve`; settings changes terminate and wait for that helper
/// process before starting another. Do not repeatedly call this from an embedded
/// runtime that survives configuration changes. Peer EOF closes VHCI before the
/// loss callback; process exit also closes all owned controller descriptors.
pub fn attach_external(
    endpoint: SocketAddr,
    on_adapter: impl Fn(u16) + Send + Sync + 'static,
    on_lost: impl Fn() + Send + 'static,
) -> std::io::Result<()> {
    external::endpoint(endpoint)?;
    std::thread::Builder::new()
        .name("stock-hci".into())
        .spawn(move || {
            loop {
                match tunnel_external(endpoint, &on_adapter) {
                    Ok(true) => on_lost(),
                    Ok(false) | Err(TunnelError::NoDongle(_)) => {}
                    Err(error) => eprintln!("[bt] external controller: {error}"),
                }
                std::thread::sleep(RETRY);
            }
        })?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Link,
    External,
}

#[derive(Debug)]
pub enum TunnelError {
    NoDongle(std::io::Error),
    Failed(String),
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDongle(e) => write!(f, "no dongle in reach: {e}"),
            Self::Failed(e) => f.write_str(e),
        }
    }
}

pub fn tunnel(on_adapter: &(impl Fn(u16) + Sync)) -> Result<bool, TunnelError> {
    let stream =
        link::connect(livi_net::port::HCI, CONNECT_TIMEOUT).map_err(TunnelError::NoDongle)?;
    tunnel_stream(stream, Mode::Link, on_adapter)
}

pub fn tunnel_external(
    endpoint: SocketAddr,
    on_adapter: &(impl Fn(u16) + Sync),
) -> Result<bool, TunnelError> {
    external::endpoint(endpoint).map_err(|e| TunnelError::Failed(e.to_string()))?;
    let stream =
        TcpStream::connect_timeout(&endpoint, CONNECT_TIMEOUT).map_err(TunnelError::NoDongle)?;
    tunnel_stream(stream, Mode::External, on_adapter)
}

fn tunnel_stream(
    stream: TcpStream,
    mode: Mode,
    on_adapter: &(impl Fn(u16) + Sync),
) -> Result<bool, TunnelError> {
    let failed = TunnelError::Failed;
    stream
        .set_nodelay(true)
        .map_err(|e| failed(format!("nodelay: {e}")))?;
    if let Err(e) = tunnel::notice_loss(&stream, Some(GIVE_UP)) {
        eprintln!("[bt] tunnel timeout: {e}");
    }
    let mut dev = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(if mode == Mode::External {
            libc::O_NONBLOCK
        } else {
            0
        })
        .open(VHCI)
        .map_err(|e| failed(format!("{VHCI}: {e}")))?;
    dev.write_all(&CREATE_PRIMARY)
        .map_err(|e| failed(format!("{VHCI}: no adapter: {e}")))?;
    let made = AtomicBool::new(false);
    let named = |index| {
        made.store(true, Ordering::Relaxed);
        on_adapter(index);
    };
    match mode {
        Mode::Link => pump(dev, stream, &named),
        Mode::External => pump_external(dev, stream, &named),
    }
    println!("[bt] tunnel closed");
    Ok(made.load(Ordering::Relaxed))
}

fn pump_external(dev: File, stream: TcpStream, named: &(impl Fn(u16) + Sync)) {
    pump_mode(dev, stream, named, Mode::External);
}

fn pump(dev: File, stream: TcpStream, named: &(impl Fn(u16) + Sync)) {
    pump_mode(dev, stream, named, Mode::Link);
}

fn pump_mode(dev: File, stream: TcpStream, named: &(impl Fn(u16) + Sync), mode: Mode) {
    let (Ok(out), Ok(reader)) = (stream.try_clone(), dev.try_clone()) else {
        eprintln!("[bt] cannot split the tunnel");
        return;
    };
    let stop = AtomicBool::new(false);
    let session = external::Session::default();
    let out = Mutex::new(out);
    std::thread::scope(|threads| {
        threads.spawn(|| {
            out_bound(reader, &out, &stop, named, mode, &session);
            // A rejected command or a device error must also release the inbound
            // reader. TCP keepalive alone does not detect a healthy idle peer.
            let _ = stream.shutdown(std::net::Shutdown::Both);
        });
        in_bound(dev, &stream, &out, mode, &session);
        stop.store(true, Ordering::Relaxed);
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
}

fn out_bound(
    mut dev: impl Read + AsRawFd,
    out: &Mutex<TcpStream>,
    stop: &AtomicBool,
    named: &impl Fn(u16),
    mode: Mode,
    session: &external::Session,
) {
    let mut buf = [0u8; PACKET_MAX];
    while !stop.load(Ordering::Relaxed) {
        if !readable(dev.as_raw_fd(), POLL_MS) {
            continue;
        }
        let n = match dev.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => {
                eprintln!("[bt] read {VHCI}: {e}");
                return;
            }
        };
        if buf[0] == VENDOR_PKT {
            if n >= 4 {
                let index = u16::from_le_bytes([buf[2], buf[3]]);
                println!("[bt] the dongle's controller is hci{index}");
                unblock(index);
                named(index);
            }
            continue;
        }
        if mode == Mode::External && !session.outgoing(&buf[..n]) {
            if buf[0] == COMMAND && n >= 3 {
                eprintln!(
                    "[bt] external controller rejected opcode={:04x}",
                    u16::from_le_bytes([buf[1], buf[2]])
                );
            } else {
                eprintln!("[bt] external controller rejected outgoing type={}", buf[0]);
            }
            return;
        }
        if let Err(e) = send(out, &buf[..n]) {
            eprintln!("[bt] send: {e}");
            return;
        }
    }
}

fn send(out: &Mutex<TcpStream>, pkt: &[u8]) -> std::io::Result<()> {
    out.lock().unwrap().write_all(&tunnel::frame(pkt))
}

fn unblock(index: u16) {
    let want = format!("hci{index}");
    let Ok(entries) = std::fs::read_dir(RFKILL) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if std::fs::read_to_string(path.join("name")).is_ok_and(|n| n.trim() == want) {
            if let Err(e) = std::fs::write(path.join("soft"), b"0") {
                eprintln!("[bt] {want} stays blocked: {e}");
            }
            return;
        }
    }
}

fn in_bound(
    mut dev: File,
    stream: &TcpStream,
    out: &Mutex<TcpStream>,
    mode: Mode,
    session: &external::Session,
) {
    let mut input = stream;
    let mut buf = [0u8; PACKET_MAX];
    let mut own_orders = 0u32;
    loop {
        let n = match tunnel::receive(&mut input, &mut buf) {
            Ok(n) => n,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    eprintln!("[bt] receive: {e}");
                }
                return;
            }
        };
        if mode == Mode::External && !session.incoming(&mut buf[..n]) {
            eprintln!("[bt] external controller rejected unsupported incoming packet");
            return;
        }
        if own_orders > 0 && answers(&buf[..n], WRITE_VOICE_SETTING) {
            own_orders -= 1;
            continue;
        }
        if let Some(order) = fit_to_vhci(&mut buf[..n]) {
            if let Err(e) = send(out, &order) {
                eprintln!("[bt] send: {e}");
                return;
            }
            own_orders += 1;
        }
        if let Err(e) = dev.write_all(&buf[..n]) {
            eprintln!("[bt] write /dev/vhci: {e}");
            return;
        }
    }
}

const EVENT: u8 = 0x04;
const COMMAND: u8 = 0x01;
const COMMAND_COMPLETE: u8 = 0x0e;
const READ_LOCAL_COMMANDS: u16 = 0x1002;
const READ_VOICE_SETTING: u16 = 0x0c25;
const WRITE_VOICE_SETTING: u16 = 0x0c26;
const SYNC_FLOWCTL: (usize, u8) = (7 + 10, 1 << 4);
const VOICE_16BIT: u16 = 0x0060;

fn answers(pkt: &[u8], opcode: u16) -> bool {
    pkt.len() >= 7
        && pkt[0] == EVENT
        && pkt[1] == COMMAND_COMPLETE
        && u16::from_le_bytes([pkt[4], pkt[5]]) == opcode
}

fn fit_to_vhci(pkt: &mut [u8]) -> Option<Vec<u8>> {
    if pkt.len() < 9 || pkt[6] != 0 {
        return None;
    }
    if answers(pkt, READ_LOCAL_COMMANDS) && pkt.len() > SYNC_FLOWCTL.0 {
        pkt[SYNC_FLOWCTL.0] &= !SYNC_FLOWCTL.1;
        return None;
    }
    if answers(pkt, READ_VOICE_SETTING) && pkt[7..9] != VOICE_16BIT.to_le_bytes() {
        pkt[7..9].copy_from_slice(&VOICE_16BIT.to_le_bytes());
        let mut order = vec![COMMAND];
        order.extend_from_slice(&WRITE_VOICE_SETTING.to_le_bytes());
        order.push(2);
        order.extend_from_slice(&VOICE_16BIT.to_le_bytes());
        return Some(order);
    }
    None
}

fn readable(fd: RawFd, ms: i32) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&raw mut p, 1, ms) > 0 }
}

#[cfg(test)]
mod tests {
    use super::{answers, fit_to_vhci};

    fn complete(opcode: u16, params: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0x04, 0x0e, (4 + params.len()) as u8, 5];
        pkt.extend_from_slice(&opcode.to_le_bytes());
        pkt.push(0);
        pkt.extend_from_slice(params);
        pkt
    }

    #[test]
    fn readiness_races_do_not_end_a_nonblocking_hci_pump() {
        use std::fs::File;
        use std::io::{self, Read};
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::{AsRawFd, OwnedFd, RawFd};
        use std::os::unix::net::UnixDatagram;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;
        struct TransientRead {
            file: File,
            errors: usize,
        }
        impl AsRawFd for TransientRead {
            fn as_raw_fd(&self) -> RawFd {
                self.file.as_raw_fd()
            }
        }
        impl Read for TransientRead {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.errors += 1;
                match self.errors {
                    1 => Err(io::ErrorKind::WouldBlock.into()),
                    2 => Err(io::ErrorKind::Interrupted.into()),
                    _ => self.file.read(buf),
                }
            }
        }
        let (device, kernel) = UnixDatagram::pair().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut peer = listener.accept().unwrap().0;
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let pump = std::thread::spawn(move || {
            super::out_bound(
                TransientRead {
                    file: File::from(OwnedFd::from(device)),
                    errors: 0,
                },
                &Mutex::new(stream),
                &stop,
                &|_| {},
                super::Mode::Link,
                &super::external::Session::default(),
            )
        });
        kernel.send(&[1, 1, 16, 0]).unwrap();
        let mut frame = [0; 6];
        let received = peer.read_exact(&mut frame);
        stopped.store(true, Ordering::Relaxed);
        pump.join().unwrap();
        received.unwrap();
        assert_eq!(frame, [0, 4, 1, 1, 16, 0]);
    }

    #[test]
    fn call_audio_flow_control_is_not_offered() {
        let mut pkt = complete(0x1002, &[0xff; 64]);
        assert_eq!(fit_to_vhci(&mut pkt), None);
        assert_eq!(pkt[7 + 10], 0xef);
        assert!(
            pkt[7..]
                .iter()
                .enumerate()
                .all(|(i, b)| i == 10 || *b == 0xff)
        );
    }

    #[test]
    fn an_8_bit_controller_is_set_to_16_bit_and_reads_so() {
        let mut pkt = complete(0x0c25, &[0x00, 0x00]);
        let order = fit_to_vhci(&mut pkt);
        assert_eq!(&pkt[7..9], &[0x60, 0x00]);
        assert_eq!(order, Some(vec![0x01, 0x26, 0x0c, 0x02, 0x60, 0x00]));
    }

    #[test]
    fn a_16_bit_controller_is_left_alone() {
        let mut pkt = complete(0x0c25, &[0x60, 0x00]);
        let was = pkt.clone();
        assert_eq!(fit_to_vhci(&mut pkt), None);
        assert_eq!(pkt, was);
    }

    #[test]
    fn a_failed_or_other_answer_is_left_alone() {
        let mut failed = complete(0x0c25, &[0x00, 0x00]);
        failed[6] = 0x0c;
        let mut other = complete(0x1005, &[0xfd, 0x03, 0xff, 0x04, 0x00, 0x04, 0x00]);
        let (was_failed, was_other) = (failed.clone(), other.clone());
        assert_eq!(fit_to_vhci(&mut failed), None);
        assert_eq!(fit_to_vhci(&mut other), None);
        assert_eq!(failed, was_failed);
        assert_eq!(other, was_other);
    }

    #[test]
    fn the_answer_to_our_own_order_is_recognised() {
        assert!(answers(&complete(0x0c26, &[]), 0x0c26));
        assert!(!answers(&complete(0x0c25, &[0, 0]), 0x0c26));
        assert!(!answers(&[0x02, 0x0e, 0x04, 5, 0x26, 0x0c, 0], 0x0c26));
    }
}
