// SPDX-FileCopyrightText: 2026 LIVI contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

//! An owned Ethernet tunnel to the stock AX520's existing wireless network.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAC: [u8; 6] = [0x02, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5];
const FRAME_MAX: usize = 1514;
const IFACE: &str = "ax520cp0";
const MAC_TEXT: &str = "02:a1:b2:c3:d4:e5";
const PEER_PORT: u16 = 15038;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const RETRY: Duration = Duration::from_secs(2);
const POLL_MS: i32 = 100;

#[derive(Default)]
struct Shared {
    stop: AtomicBool,
    ready: AtomicBool,
    mutex: Mutex<()>,
    wake: Condvar,
}

impl Shared {
    fn cancelled(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn cancel(&self) {
        // Use the waiter's mutex so cancellation cannot race between its
        // predicate check and going to sleep.
        let _lock = self.mutex.lock().unwrap_or_else(|e| e.into_inner());
        self.stop.store(true, Ordering::Release);
        self.wake.notify_all();
    }

    fn wait(&self, within: Duration) {
        let lock = self.mutex.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self
            .wake
            .wait_timeout_while(lock, within, |_| !self.cancelled())
            .unwrap_or_else(|e| e.into_inner());
    }
}

/// Owns one reconnecting stock network attachment. Dropping the handle cancels
/// retries and the nonblocking pump, closes its socket and nonpersistent TAP,
/// and joins the worker. Network waits are bounded by 500 ms for a connection
/// and 100 ms while pumping; kernel interface operations must also complete.
/// This handle must be retained for as long as the external network is needed.
pub struct Handle {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

impl Handle {
    /// True only while this worker owns a configured, up TAP and a connected
    /// relay. This does not establish an IPv6 address or phone reachability;
    /// callers must still check carrier and non-tentative link-local readiness.
    pub fn is_ready(&self) -> bool {
        self.shared.ready.load(Ordering::Acquire)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shared.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Attach the stock dongle's existing wireless network through the fixed local
/// ADB forward. No access point, DHCP client, IPv4 address, default route, or DNS
/// configuration is created. An existing interface/address/route is never
/// adopted. The root helper owns this worker independently of wired auth.
///
/// Startup does not wait for the relay: an unavailable peer is retried in the
/// background. Initial ownership/permission failures are reported immediately.
pub fn attach_external() -> io::Result<Handle> {
    // SAFETY: geteuid has no arguments or side effects.
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stock TAP attachment requires root",
        ));
    }
    preflight_system()?;
    spawn_worker(session, RETRY)
}

fn spawn_worker<F>(mut session: F, retry: Duration) -> io::Result<Handle>
where
    F: FnMut(&Shared) -> io::Result<()> + Send + 'static,
{
    let shared = Arc::new(Shared::default());
    let state = shared.clone();
    let worker = thread::Builder::new()
        .name("stock-network".into())
        .spawn(move || {
            let mut last_error = None;
            while !state.cancelled() {
                let result = session(&state);
                // Session resources have already been dropped before another
                // attempt. Never allow readiness to outlive a failed session.
                state.ready.store(false, Ordering::Release);
                match result {
                    Ok(()) => last_error = None,
                    Err(error) if !state.cancelled() => {
                        let failure = (error.kind(), error.to_string());
                        if last_error.as_ref() != Some(&failure) {
                            eprintln!("[stock-net] relay unavailable: {error}");
                            last_error = Some(failure);
                        }
                    }
                    Err(_) => {}
                }
                state.wait(retry);
            }
        })?;
    Ok(Handle {
        shared,
        worker: Some(worker),
    })
}

fn preflight_system() -> io::Result<()> {
    preflight(
        Path::new("/sys/class/net"),
        [
            Path::new("/proc/net/route"),
            Path::new("/proc/net/ipv6_route"),
        ],
    )
}

fn session(shared: &Shared) -> io::Result<()> {
    // Recheck on every retry; another process may now own the reserved name.
    preflight_system()?;
    let peer = TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, PEER_PORT)),
        CONNECT_TIMEOUT,
    )?;
    peer.set_nodelay(true)?;
    peer.set_nonblocking(true)?;
    if shared.cancelled() {
        return Ok(());
    }
    let tap = open_tap()?;
    configure_tap()?;
    run_session(shared, tap, peer)
}

fn run_session<T: AsRawFd>(shared: &Shared, tap: T, mut peer: TcpStream) -> io::Result<()> {
    struct Ready<'a>(&'a AtomicBool);
    impl Drop for Ready<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    if shared.cancelled() {
        return Ok(());
    }
    let _ready = Ready(&shared.ready);
    shared.ready.store(true, Ordering::Release);
    relay(tap.as_raw_fd(), &mut peer, shared).map(|_| ())
    // The readiness guard, peer and TAP are owned here. All are dropped on
    // EOF, cancellation, malformed input or any IO failure before retrying.
}

fn preflight(net: &Path, routes: [&Path; 2]) -> io::Result<()> {
    if net.join(IFACE).try_exists()? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "reserved TAP interface already exists",
        ));
    }
    for entry in fs::read_dir(net)? {
        let address = fs::read_to_string(entry?.path().join("address"))?;
        if address.trim().eq_ignore_ascii_case(MAC_TEXT) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "reserved TAP address already exists",
            ));
        }
    }
    for path in routes {
        if route_conflicts(&fs::read_to_string(path)?, IFACE) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "reserved TAP has an existing route",
            ));
        }
    }
    Ok(())
}

fn request() -> libc::ifreq {
    // SAFETY: zero is a valid empty ioctl request, populated before every use.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(IFACE.bytes()) {
        *slot = byte as libc::c_char;
    }
    request
}

fn control(fd: RawFd, operation: libc::c_ulong, request: &mut libc::ifreq) -> io::Result<()> {
    // SAFETY: the request matches these interface ioctl operations and remains live.
    if unsafe { libc::ioctl(fd, operation, request) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn open_tap() -> io::Result<OwnedFd> {
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TUN_EXCL: libc::c_short = 0x8000u16 as libc::c_short;
    // SAFETY: a fixed nul-terminated kernel device name and valid flags.
    let fd = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a new fd exclusively owned here.
    let tap = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = request();
    req.ifr_ifru.ifru_flags =
        libc::IFF_TAP as libc::c_short | libc::IFF_NO_PI as libc::c_short | IFF_TUN_EXCL;
    control(tap.as_raw_fd(), TUNSETIFF, &mut req)?;
    // No TUNSETPERSIST: even a signal or process crash closes the fd and removes the TAP.
    Ok(tap)
}

fn configure_tap() -> io::Result<()> {
    // SAFETY: a local IPv4 datagram socket used only for interface ioctls.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a new fd exclusively owned here.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = request();
    // SAFETY: zero initializes every sockaddr byte; the Ethernet family is set next.
    let mut address: libc::sockaddr = unsafe { std::mem::zeroed() };
    address.sa_family = libc::ARPHRD_ETHER;
    for (slot, byte) in address.sa_data.iter_mut().zip(MAC) {
        *slot = byte as libc::c_char;
    }
    req.ifr_ifru.ifru_hwaddr = address;
    control(socket.as_raw_fd(), libc::SIOCSIFHWADDR, &mut req)?;
    req.ifr_ifru.ifru_mtu = 1500;
    control(socket.as_raw_fd(), libc::SIOCSIFMTU, &mut req)?;
    // This worker owns this new interface. Allow only its link-local IPv6 address;
    // do not accept advertised default routes, prefixes, or DNS configuration.
    for (name, value) in [
        ("disable_ipv6", "0"),
        ("addr_gen_mode", "0"),
        ("accept_ra", "0"),
        ("autoconf", "0"),
        ("router_solicitations", "0"),
    ] {
        fs::write(format!("/proc/sys/net/ipv6/conf/{IFACE}/{name}"), value)?;
    }
    control(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut req)?;
    // SAFETY: SIOCGIFFLAGS initialized the flags member immediately above.
    req.ifr_ifru.ifru_flags = unsafe { req.ifr_ifru.ifru_flags } | libc::IFF_UP as libc::c_short;
    control(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &mut req)
}

fn allowed(frame: &[u8], from_tap: bool) -> bool {
    if !(14..=FRAME_MAX).contains(&frame.len())
        || !matches!(
            u16::from_be_bytes([frame[12], frame[13]]),
            0x0800 | 0x0806 | 0x86dd
        )
    {
        return false;
    }
    let dst = &frame[..6];
    let src = &frame[6..12];
    if src == [0; 6] || src[0] & 1 != 0 || dst == [0; 6] {
        return false;
    }
    if from_tap {
        src == MAC && dst != MAC
    } else {
        src != MAC && (dst == MAC || dst[0] & 1 != 0)
    }
}

fn route_conflicts(table: &str, iface: &str) -> bool {
    table
        .lines()
        .any(|line| line.split_whitespace().any(|field| field == iface))
}

struct Decoder {
    header: [u8; 2],
    header_len: usize,
    frame: [u8; FRAME_MAX],
    frame_len: usize,
    want: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            header: [0; 2],
            header_len: 0,
            frame: [0; FRAME_MAX],
            frame_len: 0,
            want: 0,
        }
    }
}

impl Decoder {
    fn needed(&self) -> usize {
        if self.header_len < 2 {
            2 - self.header_len
        } else {
            self.want - self.frame_len
        }
    }

    fn push(&mut self, bytes: &[u8]) -> io::Result<Option<Vec<u8>>> {
        if bytes.len() > self.needed() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame boundary exceeded",
            ));
        }
        if self.header_len < 2 {
            self.header[self.header_len..self.header_len + bytes.len()].copy_from_slice(bytes);
            self.header_len += bytes.len();
            if self.header_len == 2 {
                self.want = usize::from(u16::from_be_bytes(self.header));
                if !(14..=FRAME_MAX).contains(&self.want) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Ethernet frame length",
                    ));
                }
            }
            return Ok(None);
        }
        self.frame[self.frame_len..self.frame_len + bytes.len()].copy_from_slice(bytes);
        self.frame_len += bytes.len();
        if self.frame_len != self.want {
            return Ok(None);
        }
        let complete = self.frame[..self.want].to_vec();
        self.header_len = 0;
        self.frame_len = 0;
        self.want = 0;
        Ok(Some(complete))
    }
    fn eof(&self) -> io::Result<()> {
        if self.header_len == 0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated Ethernet frame",
            ))
        }
    }
}

#[derive(Debug, Default)]
struct Counters {
    sent: u64,
    received: u64,
    dropped: u64,
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    )
}

fn relay(tap: RawFd, peer: &mut TcpStream, shared: &Shared) -> io::Result<Counters> {
    let mut counters = Counters::default();
    let mut decoder = Decoder::default();
    let mut outgoing = Vec::new();
    let mut written = 0;
    let mut incoming: Option<Vec<u8>> = None;
    let mut buffer = [0; FRAME_MAX + 1];
    while !shared.cancelled() {
        let mut descriptors = [
            libc::pollfd {
                fd: tap,
                events: if outgoing.is_empty() { libc::POLLIN } else { 0 }
                    | if incoming.is_some() { libc::POLLOUT } else { 0 },
                revents: 0,
            },
            libc::pollfd {
                fd: peer.as_raw_fd(),
                events: if incoming.is_none() { libc::POLLIN } else { 0 }
                    | libc::POLLRDHUP
                    | if outgoing.is_empty() {
                        0
                    } else {
                        libc::POLLOUT
                    },
                revents: 0,
            },
        ];
        // SAFETY: poll receives a valid, initialized two-element array.
        let ready = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, POLL_MS) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if transient(&error) {
                continue;
            }
            return Err(error);
        }
        if descriptors
            .iter()
            .any(|d| d.revents & (libc::POLLERR | libc::POLLNVAL) != 0)
        {
            return Err(io::Error::other("transport poll error"));
        }
        // A peer can close while the TAP queue is full. Keep watching its
        // receive half even when frame backpressure suppresses normal reads;
        // dropping the pending frame is preferable to retaining a dead TAP.
        if incoming.is_some() && descriptors[1].revents & (libc::POLLRDHUP | libc::POLLHUP) != 0 {
            return Ok(counters);
        }
        if descriptors[1].revents & libc::POLLOUT != 0 && !outgoing.is_empty() {
            match peer.write(&outgoing[written..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "peer stopped accepting frames",
                    ));
                }
                Ok(n) => {
                    written += n;
                    if written == outgoing.len() {
                        counters.sent += 1;
                        outgoing.clear();
                        written = 0;
                    }
                }
                Err(error) if transient(&error) => {}
                Err(error) => return Err(error),
            }
        }
        if descriptors[0].revents & libc::POLLOUT != 0
            && let Some(frame) = &incoming
        {
            // SAFETY: the frame buffer is valid and the caller holds the TAP fd.
            let n = unsafe { libc::write(tap, frame.as_ptr().cast(), frame.len()) };
            if n < 0 {
                let error = io::Error::last_os_error();
                if !transient(&error) {
                    return Err(error);
                }
            } else if n as usize != frame.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial TAP packet",
                ));
            } else {
                counters.received += 1;
                incoming = None;
            }
        }
        if descriptors[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 && incoming.is_none() {
            match peer.read(&mut buffer[..decoder.needed()]) {
                Ok(0) => {
                    decoder.eof()?;
                    return Ok(counters);
                }
                Ok(n) => {
                    if let Some(frame) = decoder.push(&buffer[..n])? {
                        if allowed(&frame, false) {
                            incoming = Some(frame);
                        } else {
                            counters.dropped += 1;
                        }
                    }
                }
                Err(error) if transient(&error) => {}
                Err(error) => return Err(error),
            }
        }
        if descriptors[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 && outgoing.is_empty() {
            // SAFETY: the buffer has the passed size and the caller holds the TAP fd.
            let n = unsafe { libc::read(tap, buffer.as_mut_ptr().cast(), buffer.len()) };
            if n < 0 {
                let error = io::Error::last_os_error();
                if !transient(&error) {
                    return Err(error);
                }
            } else if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TAP closed"));
            } else if allowed(&buffer[..n as usize], true) {
                outgoing.extend_from_slice(&(n as u16).to_be_bytes());
                outgoing.extend_from_slice(&buffer[..n as usize]);
            } else {
                counters.dropped += 1;
            }
        }
    }
    Ok(counters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let ours = listener.accept().unwrap().0;
        (ours, peer)
    }

    fn packet(source: [u8; 6], destination: [u8; 6], ethertype: u16) -> Vec<u8> {
        let mut out = destination.to_vec();
        out.extend(source);
        out.extend(ethertype.to_be_bytes());
        out.extend([0x60, 0, 0, 0, 0, 0, 59, 64]);
        out
    }

    #[test]
    fn network_filter_passes_neighbor_discovery_and_only_our_unicast() {
        let phone = [0x02, 1, 2, 3, 4, 5];
        for kind in [0x0800, 0x0806, 0x86dd] {
            assert!(allowed(&packet(MAC, phone, kind), true));
            assert!(allowed(&packet(phone, MAC, kind), false));
            assert!(allowed(&packet(phone, [0xff; 6], kind), false));
            assert!(allowed(&packet(MAC, [0x33, 0x33, 0, 0, 0, 1], kind), true));
        }
        assert!(!allowed(&packet(phone, MAC, 0x888e), false));
        assert!(!allowed(&packet(phone, MAC, 0x8100), false));
        assert!(!allowed(&packet(MAC, [0xff; 6], 0x86dd), false));
        assert!(!allowed(
            &packet(phone, [0x02, 9, 9, 9, 9, 9], 0x86dd),
            false
        ));
        assert!(!allowed(&packet([0xff; 6], MAC, 0x86dd), false));
        assert!(!allowed(&packet([0; 6], MAC, 0x86dd), false));
        assert!(!allowed(&packet(MAC, MAC, 0x86dd), true));
        assert!(!allowed(&packet(MAC, [0; 6], 0x86dd), true));
        assert!(!allowed(&[0; 13], false));
        let mut too_big = packet(phone, MAC, 0x86dd);
        too_big.resize(1515, 0);
        assert!(!allowed(&too_big, false));
    }

    #[test]
    fn decoder_keeps_partial_header_and_body_without_losing_bytes() {
        let frame = packet([0x02, 1, 2, 3, 4, 5], MAC, 0x86dd);
        let mut decoder = Decoder::default();
        assert_eq!(decoder.push(&[0]).unwrap(), None);
        assert_eq!(decoder.push(&[22]).unwrap(), None);
        assert_eq!(decoder.push(&frame[..7]).unwrap(), None);
        assert_eq!(decoder.push(&frame[7..]).unwrap(), Some(frame));
        assert!(decoder.eof().is_ok());
    }

    #[test]
    fn decoder_rejects_invalid_lengths_and_truncated_frame() {
        for header in [[0, 0], [0, 13], [5, 235], [255, 255]] {
            assert_eq!(
                Decoder::default().push(&header).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        let mut decoder = Decoder::default();
        assert_eq!(decoder.push(&[0, 22]).unwrap(), None);
        assert_eq!(
            decoder.eof().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn only_routes_owned_by_the_reserved_name_conflict() {
        assert!(route_conflicts(
            "ax520cp0 00000000 00000000 0001\n",
            "ax520cp0"
        ));
        assert!(route_conflicts(
            "fe800000 40 0000 00 00000000 00000000 00000000 00000001 ax520cp0\n",
            "ax520cp0"
        ));
        assert!(!route_conflicts(
            "eth0 00000000 12345678 0003\n",
            "ax520cp0"
        ));
        assert!(!route_conflicts(
            "ax520cp01 00000000 00000000 0001\n",
            "ax520cp0"
        ));
    }

    #[test]
    fn relay_moves_ethernet_both_directions_and_drops_foreign_sources() {
        let (tap, phone) = UnixDatagram::pair().unwrap();
        tap.set_nonblocking(true).unwrap();
        phone
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (mut ours, mut peer) = tcp_pair();
        ours.set_nonblocking(true).unwrap();
        let worker =
            std::thread::spawn(move || relay(tap.as_raw_fd(), &mut ours, &Shared::default()));
        let bad = packet([0x02, 9, 9, 9, 9, 9], [0xff; 6], 0x86dd);
        phone.send(&bad).unwrap();
        let good = packet(MAC, [0xff; 6], 0x86dd);
        phone.send(&good).unwrap();
        let mut wire = vec![0; 24];
        peer.read_exact(&mut wire).unwrap();
        assert_eq!(&wire[..2], &[0, 22]);
        assert_eq!(&wire[2..], good);
        let reply = packet([0x02, 1, 2, 3, 4, 5], MAC, 0x86dd);
        peer.write_all(&[0]).unwrap();
        peer.write_all(&[22]).unwrap();
        peer.write_all(&reply[..4]).unwrap();
        peer.write_all(&reply[4..]).unwrap();
        let mut got = [0; 1514];
        let n = phone.recv(&mut got).unwrap();
        assert_eq!(&got[..n], reply);
        drop(peer);
        let counters = worker.join().unwrap().unwrap();
        assert_eq!(
            (counters.sent, counters.received, counters.dropped),
            (1, 1, 1)
        );
    }

    #[test]
    fn peer_eof_in_a_frame_is_reported_as_truncation() {
        let (tap, _phone) = UnixDatagram::pair().unwrap();
        tap.set_nonblocking(true).unwrap();
        let (mut ours, mut peer) = tcp_pair();
        ours.set_nonblocking(true).unwrap();
        peer.write_all(&[0, 22, 1, 2]).unwrap();
        drop(peer);
        assert_eq!(
            relay(tap.as_raw_fd(), &mut ours, &Shared::default())
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn preflight_refuses_an_existing_interface_address_or_route() {
        let root = std::env::temp_dir().join(format!(
            "livi-external-net-preflight-{}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        struct Remove(std::path::PathBuf);
        impl Drop for Remove {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _remove = Remove(root.clone());
        let net = root.join("net");
        std::fs::create_dir(&net).unwrap();
        let route4 = root.join("route");
        let route6 = root.join("ipv6_route");
        std::fs::write(&route4, "eth0 00000000 12345678 0003\n").unwrap();
        std::fs::write(&route6, "").unwrap();
        let routes = [route4.as_path(), route6.as_path()];
        assert!(preflight(&net, routes).is_ok());
        std::fs::create_dir(net.join(IFACE)).unwrap();
        assert_eq!(
            preflight(&net, routes).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        std::fs::remove_dir(net.join(IFACE)).unwrap();
        std::fs::create_dir(net.join("other")).unwrap();
        std::fs::write(net.join("other/address"), "02:a1:b2:c3:d4:e5\n").unwrap();
        assert_eq!(
            preflight(&net, routes).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        std::fs::write(net.join("other/address"), "02:01:02:03:04:05\n").unwrap();
        std::fs::write(&route6, "fe80 40 0000 00 00000000 ax520cp0\n").unwrap();
        assert_eq!(
            preflight(&net, routes).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn drop_cancels_a_stalled_partial_frame_and_closes_the_peer() {
        let (tap, _other) = UnixDatagram::pair().unwrap();
        tap.set_nonblocking(true).unwrap();
        let (ours, mut peer) = tcp_pair();
        ours.set_nonblocking(true).unwrap();
        let mut resources = Some((tap, ours));
        let (entered, wait) = std::sync::mpsc::channel();
        let handle = spawn_worker(
            move |shared| {
                let (tap, peer) = resources.take().unwrap();
                entered.send(()).unwrap();
                run_session(shared, tap, peer)
            },
            Duration::from_secs(60),
        )
        .unwrap();
        wait.recv_timeout(Duration::from_secs(1)).unwrap();
        peer.write_all(&[0]).unwrap();
        let began = std::time::Instant::now();
        drop(handle);
        assert!(began.elapsed() < Duration::from_secs(1));
        let mut byte = [0];
        match peer.read(&mut byte) {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            result => panic!("owned peer did not close: {result:?}"),
        }
    }

    #[test]
    fn cancellation_wakes_a_long_retry_wait() {
        let (attempted, wait) = std::sync::mpsc::channel();
        let handle = spawn_worker(
            move |_| {
                attempted.send(()).unwrap();
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "fixture relay absent",
                ))
            },
            Duration::from_secs(60),
        )
        .unwrap();
        wait.recv_timeout(Duration::from_secs(1)).unwrap();
        // Give the worker a chance to enter the retry wait; cancellation before
        // waiting is also required to work without a lost wakeup.
        std::thread::sleep(Duration::from_millis(30));
        assert!(!handle.is_ready());
        let began = std::time::Instant::now();
        drop(handle);
        assert!(began.elapsed() < Duration::from_millis(500));
    }

    struct CountedTap(UnixDatagram, Arc<std::sync::atomic::AtomicUsize>);
    impl AsRawFd for CountedTap {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
    }
    impl Drop for CountedTap {
        fn drop(&mut self) {
            self.1.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn eof_and_errors_release_old_transports_before_reconnect_and_drop_closes_the_new_one() {
        let removed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counts = removed.clone();
        let (opened, wait) = std::sync::mpsc::channel();
        let handle = spawn_worker(
            move |shared| {
                let (tap, other) = UnixDatagram::pair()?;
                tap.set_nonblocking(true)?;
                other.set_read_timeout(Some(Duration::from_secs(2)))?;
                let (ours, peer) = tcp_pair();
                ours.set_nonblocking(true)?;
                opened.send((peer, other)).unwrap();
                run_session(shared, CountedTap(tap, counts.clone()), ours)
            },
            Duration::from_millis(10),
        )
        .unwrap();
        for attempt in 0..3 {
            let (mut peer, other) = wait.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(removed.load(Ordering::SeqCst), attempt);
            // Real traffic establishes that the session reached readiness.
            let frame = packet(MAC, [0xff; 6], 0x86dd);
            other.send(&frame).unwrap();
            let mut wire = [0; 24];
            peer.read_exact(&mut wire).unwrap();
            assert_eq!(&wire[..2], &[0, 22]);
            assert_eq!(&wire[2..], frame);
            assert!(handle.is_ready());
            if attempt < 2 {
                if attempt == 1 {
                    // EOF inside a frame must also release/reconnect.
                    peer.write_all(&[0, 22, 1, 2]).unwrap();
                }
                peer.shutdown(std::net::Shutdown::Write).unwrap();
                assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            } else {
                let shared = handle.shared.clone();
                let began = std::time::Instant::now();
                drop(handle);
                assert!(began.elapsed() < Duration::from_secs(1));
                assert!(!shared.ready.load(Ordering::Acquire));
                assert_eq!(peer.read(&mut [0]).unwrap(), 0);
                break;
            }
        }
        assert_eq!(removed.load(Ordering::SeqCst), 3);
    }
    #[test]
    fn peer_half_close_releases_a_session_even_when_tap_receive_queue_is_full() {
        let (tap, _other) = UnixDatagram::pair().unwrap();
        tap.set_nonblocking(true).unwrap();
        let filler = [0; 1514];
        let mut saturated = false;
        for _ in 0..10_000 {
            match tap.send(&filler) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    saturated = true;
                    break;
                }
                Err(error) => panic!("saturating TAP fixture: {error}"),
            }
        }
        assert!(saturated, "fixture must exert real backpressure");
        let (ours, mut peer) = tcp_pair();
        ours.set_nonblocking(true).unwrap();
        let shared = Arc::new(Shared::default());
        let state = shared.clone();
        let (finished, wait) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            finished.send(run_session(&state, tap, ours)).unwrap();
        });
        let frame = packet([0x02, 1, 2, 3, 4, 5], MAC, 0x86dd);
        peer.write_all(&[0, 22]).unwrap();
        peer.write_all(&frame).unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let result = wait.recv_timeout(Duration::from_millis(500));
        // Ensure the regression failure itself cannot leave a test worker alive.
        shared.cancel();
        worker.join().unwrap();
        assert!(result.is_ok(), "peer EOF retained a blocked TAP session");
        result.unwrap().unwrap();
        assert!(!shared.ready.load(Ordering::Acquire));
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}
