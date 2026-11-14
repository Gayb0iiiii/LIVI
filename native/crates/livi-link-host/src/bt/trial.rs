// SPDX-FileCopyrightText: 2026 LIVI contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

//! A finite, metadata-only raw VHCI transport proof. It does not pair phones.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const CREATE_RAW: [u8; 2] = [0xff, 0x80];
const READ_VERSION: [u8; 4] = [0x01, 0x01, 0x10, 0x00];
const STEP_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, PartialEq, Eq)]
pub struct Version {
    pub hci_version: u8,
    pub manufacturer: u16,
}

#[derive(Debug)]
pub struct Probe {
    pub index: u16,
    pub version: Version,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn version(packet: &[u8]) -> io::Result<Version> {
    if packet.len() != 15 || packet[..3] != [4, 14, 12] || packet[4..7] != [1, 16, 0] {
        return Err(invalid("expected successful ReadLocalVersion completion"));
    }
    Ok(Version {
        hci_version: packet[7],
        manufacturer: u16::from_le_bytes([packet[11], packet[12]]),
    })
}

fn with_deadline<T>(
    stream: &TcpStream,
    deadline: Instant,
    run: impl FnOnce() -> T,
) -> io::Result<T> {
    let control = stream.try_clone()?;
    let (stop, stopped) = mpsc::channel();
    Ok(std::thread::scope(|threads| {
        threads.spawn(move || {
            if stopped.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                == Err(mpsc::RecvTimeoutError::Timeout)
            {
                let _ = control.shutdown(Shutdown::Both);
            }
        });
        let result = run();
        let _ = stop.send(());
        result
    }))
}

fn timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "raw VHCI trial deadline")
}

#[repr(C)]
struct HciAddress {
    family: libc::sa_family_t,
    index: u16,
    channel: u16,
}

fn user_channel(index: u16, deadline: Instant) -> io::Result<OwnedFd> {
    loop {
        // SAFETY: the kernel returns a new socket with no retained pointers.
        let fd = unsafe {
            libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                1,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this socket is newly created and exclusively owned here.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let address = HciAddress {
            family: libc::AF_BLUETOOTH as _,
            index,
            channel: 1,
        };
        // SAFETY: HciAddress exactly matches Linux sockaddr_hci and stays live.
        let result = unsafe {
            libc::bind(
                fd,
                (&raw const address).cast(),
                std::mem::size_of::<HciAddress>() as _,
            )
        };
        if result == 0 {
            return Ok(socket);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EBUSY) {
            return Err(error);
        }
        if Instant::now() >= deadline {
            return Err(timeout());
        }
        drop(socket);
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn query_version(socket: &OwnedFd, deadline: Instant) -> io::Result<Version> {
    // SAFETY: a live owned socket and a constant, fully initialized HCI command.
    let sent = unsafe {
        libc::send(
            socket.as_raw_fd(),
            READ_VERSION.as_ptr().cast(),
            READ_VERSION.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != READ_VERSION.len() {
        return Err(invalid("short HCI command write"));
    }
    let mut packet = [0u8; 260];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(timeout());
        }
        let mut ready = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd remains live through poll.
        let polled = unsafe { libc::poll(&raw mut ready, 1, left.as_millis().min(100) as i32) };
        if polled < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if polled == 0 {
            continue;
        }
        // SAFETY: packet is a writable bounded buffer and the socket remains live.
        let size = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                packet.as_mut_ptr().cast(),
                packet.len(),
                0,
            )
        };
        if size < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(error);
        }
        let packet = &packet[..size as usize];
        if packet == [4, 15, 4, 0, 1, 1, 16] {
            continue;
        }
        return version(packet);
    }
}

/// Create an owned RAW_DEVICE controller, send one ReadLocalVersion through its
/// HCI_USER_CHANNEL, and remove it. RAW_DEVICE skips normal kernel/BlueZ setup,
/// including stored-key operations. The physical relay must enforce the same
/// metadata-only command policy; it restores the stock owner when TCP closes.
pub fn raw_probe(endpoint: SocketAddr, within: Duration) -> io::Result<Probe> {
    if !endpoint.ip().is_loopback()
        || !endpoint.is_ipv4()
        || endpoint.port() == 0
        || within.is_zero()
        || within > Duration::from_secs(90)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "loopback peer and 1..90 seconds required",
        ));
    }
    let deadline = Instant::now() + within;
    let stream = TcpStream::connect_timeout(&endpoint, STEP_TIMEOUT.min(within))?;
    stream.set_nodelay(true)?;
    let control = stream.try_clone()?;
    let mut device = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(super::VHCI)?;
    device.write_all(&CREATE_RAW)?;
    let (named, name) = mpsc::channel();
    let mut owned_index = None;
    let outcome = with_deadline(&control, deadline, || {
        std::thread::scope(|threads| {
            let pump = threads.spawn(move || {
                super::pump(device, stream, &|index| {
                    let _ = named.send(index);
                })
            });
            let result = (|| {
                let index = name
                    .recv_timeout(
                        STEP_TIMEOUT.min(deadline.saturating_duration_since(Instant::now())),
                    )
                    .map_err(|_| timeout())?;
                owned_index = Some(index);
                let socket = user_channel(index, (Instant::now() + STEP_TIMEOUT).min(deadline))?;
                let version = query_version(
                    &socket,
                    (Instant::now() + Duration::from_secs(5)).min(deadline),
                )?;
                Ok(Probe { index, version })
            })();
            let _ = control.shutdown(Shutdown::Both);
            pump.join()
                .map_err(|_| io::Error::other("VHCI pump panicked"))?;
            result
        })
    })?;
    if owned_index.is_none() {
        owned_index = name.try_recv().ok();
    }
    if let Some(index) = owned_index {
        let path = format!("/sys/class/bluetooth/hci{index}");
        let cleanup = Instant::now() + STEP_TIMEOUT;
        while fs::exists(&path)? {
            if Instant::now() >= cleanup {
                return Err(io::Error::other("owned VHCI remains after fd close"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::time::Duration;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let peer = listener.accept().unwrap().0;
        (local, peer)
    }

    #[test]
    fn existing_hci_pump_relays_framed_version_and_stops_on_disconnect() {
        use std::io::Write;
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixDatagram;
        let (stream, mut peer) = pair();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let (device, kernel) = UnixDatagram::pair().unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let file = std::fs::File::from(OwnedFd::from(device));
        let pump = std::thread::spawn(move || super::super::pump(file, stream, &|_| {}));
        kernel.send(&READ_VERSION).unwrap();
        let mut framed_command = [0; 6];
        peer.read_exact(&mut framed_command).unwrap();
        assert_eq!(framed_command, [0, 4, 1, 1, 16, 0]);
        let reply = [
            4, 14, 12, 1, 1, 16, 0, 9, 0x34, 0x12, 9, 0x5d, 0, 0x78, 0x56,
        ];
        peer.write_all(&[0, 15]).unwrap();
        peer.write_all(&reply).unwrap();
        let mut packet = [0; 32];
        let size = kernel.recv(&mut packet).unwrap();
        assert_eq!(&packet[..size], &reply);
        peer.shutdown(Shutdown::Both).unwrap();
        pump.join().unwrap();
    }

    #[test]
    fn invalid_trials_are_rejected_before_device_access() {
        for endpoint in ["192.0.2.1:15039", "[::1]:15039", "127.0.0.1:0"] {
            assert_eq!(
                raw_probe(endpoint.parse().unwrap(), Duration::from_secs(10))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        for duration in [Duration::ZERO, Duration::from_secs(91)] {
            assert_eq!(
                raw_probe("127.0.0.1:15039".parse().unwrap(), duration)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn metadata_accepts_only_successful_read_local_version_response() {
        let reply = [
            4, 14, 12, 1, 1, 16, 0, 9, 0x34, 0x12, 9, 0x5d, 0, 0x78, 0x56,
        ];
        assert_eq!(
            version(&reply).unwrap(),
            Version {
                hci_version: 9,
                manufacturer: 0x5d
            }
        );
        for (offset, value) in [(0, 2), (1, 0x15), (2, 11), (4, 2), (6, 1)] {
            let mut bad = reply;
            bad[offset] = value;
            assert!(version(&bad).is_err());
        }
        assert!(version(&reply[..14]).is_err());
    }

    #[test]
    fn deadline_interrupts_a_peer_that_never_sends_any_bytes() {
        let (mut stream, _peer) = pair();
        stream
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let control = stream.try_clone().unwrap();
        let started = Instant::now();
        let result = with_deadline(&control, started + Duration::from_millis(40), || {
            let mut byte = [0];
            stream.read_exact(&mut byte)
        })
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn completed_work_cancels_the_deadline_thread_immediately() {
        let (stream, _peer) = pair();
        let started = Instant::now();
        assert_eq!(
            with_deadline(&stream, started + Duration::from_secs(3), || 7).unwrap(),
            7
        );
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}
