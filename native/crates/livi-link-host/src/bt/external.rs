// SPDX-FileCopyrightText: 2026 LIVI contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

//! Limits of the stock-controller proxy. Host pairing owns its fresh keys;
//! controller-stored bonds and vendor command interfaces are not exported.

use std::io;
use std::net::SocketAddr;

pub(super) fn endpoint(peer: SocketAddr) -> io::Result<()> {
    if peer.is_ipv4() && peer.ip().is_loopback() && peer.port() != 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "external HCI peer must be numeric IPv4 loopback",
        ))
    }
}

fn shape(packet: &[u8]) -> bool {
    match packet.first() {
        Some(1 | 3) => packet.len() >= 4 && packet.len() == 4 + usize::from(packet[3]),
        Some(2) => {
            packet.len() >= 5
                && packet.len() == 5 + usize::from(u16::from_le_bytes([packet[3], packet[4]]))
        }
        Some(4) => packet.len() >= 3 && packet.len() == 3 + usize::from(packet[2]),
        _ => false,
    }
}

fn supported(opcode: u16) -> bool {
    !matches!(opcode, 0x0c0d | 0x0c11 | 0x0c12) && opcode >> 10 != 0x3f
}

pub(super) fn outgoing(packet: &[u8]) -> bool {
    if !shape(packet) || packet.len() > 1028 {
        return false;
    }
    match packet[0] {
        1 => {
            let opcode = u16::from_le_bytes([packet[1], packet[2]]);
            supported(opcode)
        }
        2 | 3 => true,
        _ => false,
    }
}

pub(super) fn incoming(packet: &mut [u8]) -> bool {
    if !shape(packet) {
        return false;
    }
    match packet[0] {
        2 | 3 => true,
        4 => {
            if matches!(packet[1], 0x15 | 0xff) {
                return false;
            }
            if packet[1] == 0x0e
                && (packet.len() < 6 || !supported(u16::from_le_bytes([packet[4], packet[5]])))
            {
                return false;
            }
            if packet[1] == 0x0f
                && (packet.len() != 7 || !supported(u16::from_le_bytes([packet[5], packet[6]])))
            {
                return false;
            }
            if packet.len() >= 7 && packet[1] == 0x0e && packet[4..7] == [2, 16, 0] {
                if packet.len() != 71 {
                    return false;
                }
                // Read/Write/Delete Stored Link Key are unavailable through this proxy.
                // All other capability bits and the real controller status stay intact.
                packet[7 + 6] &= !0xe0;
            }
            true
        }
        _ => false,
    }
}

#[derive(Default)]
pub(super) struct Session(std::sync::atomic::AtomicU8);
impl Session {
    pub(super) fn outgoing(&self, packet: &[u8]) -> bool {
        use std::sync::atomic::Ordering;
        if !outgoing(packet) {
            return false;
        }
        let state = self.0.load(Ordering::Acquire);
        if packet == [1, 3, 12, 0] && state != 1 {
            self.0.store(1, Ordering::Release);
            return true;
        }
        state == 2
    }
    pub(super) fn incoming(&self, packet: &mut [u8]) -> bool {
        use std::sync::atomic::Ordering;
        if !incoming(packet) {
            return false;
        }
        match self.0.load(Ordering::Acquire) {
            2 => true,
            1 if packet.len() == 7 && packet[..3] == [4, 14, 4] && packet[4..] == [3, 12, 0] => {
                self.0.store(2, Ordering::Release);
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel() -> (
        std::net::TcpStream,
        std::os::unix::net::UnixDatagram,
        std::thread::JoinHandle<()>,
    ) {
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixDatagram;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let peer = listener.accept().unwrap().0;
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let (device, kernel) = UnixDatagram::pair().unwrap();
        kernel
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let pump = std::thread::spawn(move || {
            super::super::pump_external(std::fs::File::from(OwnedFd::from(device)), stream, &|_| {})
        });
        (peer, kernel, pump)
    }

    fn reset(peer: &mut std::net::TcpStream, kernel: &std::os::unix::net::UnixDatagram) {
        use std::io::{Read, Write};
        kernel.send(&[1, 3, 12, 0]).unwrap();
        let mut command = [0; 6];
        peer.read_exact(&mut command).unwrap();
        assert_eq!(command, [0, 4, 1, 3, 12, 0]);
        let reply = [4, 14, 4, 1, 3, 12, 0];
        peer.write_all(&livi_net::tunnel::frame(&reply)).unwrap();
        let mut event = [0; 7];
        assert_eq!(kernel.recv(&mut event).unwrap(), 7);
        assert_eq!(event, reply);
    }

    #[test]
    fn blocked_command_closes_the_actual_tunnel_without_forwarding() {
        use std::io::Read;
        let (mut peer, kernel, pump) = tunnel();
        reset(&mut peer, &kernel);
        kernel.send(&[1, 0x0d, 0x0c, 0]).unwrap();
        let mut prefix = [0; 2];
        let received = peer.read(&mut prefix);
        peer.shutdown(std::net::Shutdown::Both).unwrap();
        pump.join().unwrap();
        assert_eq!(received.unwrap(), 0);
    }

    #[test]
    fn actual_tunnel_exposes_only_the_declared_proxy_capabilities() {
        use std::io::Write;
        let (mut peer, kernel, pump) = tunnel();
        reset(&mut peer, &kernel);
        let mut reply = vec![4, 14, 68, 1, 2, 16, 0];
        reply.extend([0xff; 64]);
        peer.write_all(&livi_net::tunnel::frame(&reply)).unwrap();
        let mut buf = [0; 128];
        let length = kernel.recv(&mut buf).unwrap();
        peer.shutdown(std::net::Shutdown::Both).unwrap();
        pump.join().unwrap();
        assert_eq!(length, 71);
        reply[13] = 0x1f;
        reply[17] = 0xef; // existing VHCI synchronous-flow-control compatibility
        assert_eq!(&buf[..length], reply);
    }

    #[test]
    fn a_fresh_session_requires_the_actual_first_reset_reply() {
        let session = Session::default();
        assert!(!session.outgoing(&[1, 1, 16, 0]));
        assert!(!session.incoming(&mut [4, 0x17, 6, 0, 0, 0, 0, 0, 0]));
        assert!(!session.incoming(&mut [4, 14, 4, 1, 3, 12, 0]));
        assert!(session.outgoing(&[1, 3, 12, 0]));
        assert!(!session.outgoing(&[1, 1, 16, 0]));
        assert!(!session.incoming(&mut [4, 14, 4, 1, 3, 12, 1]));
        assert!(session.incoming(&mut [4, 14, 4, 1, 3, 12, 0]));
        assert!(session.outgoing(&[1, 1, 16, 0]));
        assert!(session.incoming(&mut [4, 0x17, 6, 0, 0, 0, 0, 0, 0]));
        assert!(session.outgoing(&[1, 3, 12, 0]));
        assert!(!session.incoming(&mut [4, 0x17, 6, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn queued_stored_key_and_vendor_responses_are_not_exported() {
        assert!(!incoming(&mut [4, 0xff, 0]));
        for opcode in [0x0c0du16, 0x0c11, 0x0c12, 0xfc00, 0xffff] {
            let [low, high] = opcode.to_le_bytes();
            assert!(!incoming(&mut [4, 14, 4, 1, low, high, 0]));
            assert!(!incoming(&mut [4, 15, 4, 0, 1, low, high]));
        }
        assert!(!incoming(&mut [4, 14, 1, 0]));
        assert!(!incoming(&mut [4, 15, 1, 0]));
    }

    #[test]
    fn only_numeric_ipv4_loopback_endpoints_are_permitted() {
        assert!(endpoint("127.0.0.1:15039".parse().unwrap()).is_ok());
        for peer in ["192.0.2.1:15039", "[::1]:15039", "127.0.0.1:0"] {
            assert!(endpoint(peer.parse().unwrap()).is_err());
        }
    }

    #[test]
    fn stored_key_and_vendor_commands_never_leave_the_host() {
        for opcode in [0x0c0du16, 0x0c11, 0x0c12, 0xfc00, 0xffff] {
            let [low, high] = opcode.to_le_bytes();
            assert!(!outgoing(&[1, low, high, 0]));
        }
        assert!(outgoing(&[1, 1, 16, 0])); // ReadLocalVersion
        assert!(outgoing(&[1, 0x0c, 4, 0])); // LinkKeyNegativeReply, shape only
        assert!(!outgoing(&[1, 1, 16, 1]));
    }

    #[test]
    fn only_stored_key_capabilities_change_in_the_real_reply() {
        let mut reply = vec![4, 14, 68, 1, 2, 16, 0];
        reply.extend([0xff; 64]);
        let original = reply.clone();
        assert!(incoming(&mut reply));
        assert_eq!(reply[13], 0x1f);
        assert!(
            reply
                .iter()
                .zip(&original)
                .enumerate()
                .all(|(i, (a, b))| i == 13 || a == b)
        );
        let mut failed = original.clone();
        failed[6] = 1;
        assert!(incoming(&mut failed));
        assert_eq!(&failed[7..], &original[7..]);
        assert!(!incoming(&mut [4, 14, 4, 1, 2, 16, 0])); // truncated success
    }

    #[test]
    fn old_key_dump_is_rejected_but_pairing_and_authentication_events_are_unchanged() {
        assert!(!incoming(&mut [4, 0x15, 1, 0]));
        for mut packet in [
            vec![4, 0x17, 6, 0, 0, 0, 0, 0, 0],
            vec![
                4, 0x18, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            vec![4, 6, 3, 5, 1, 0],
        ] {
            let original = packet.clone();
            assert!(incoming(&mut packet));
            assert_eq!(packet, original);
        }
    }

    #[test]
    fn packet_shapes_and_the_stock_kernel_limit_are_enforced() {
        assert!(outgoing(&[2, 1, 0, 2, 0, 0xaa, 0xbb]));
        assert!(incoming(&mut [3, 1, 0, 1, 0xaa]));
        for mut packet in [
            vec![],
            vec![0xff, 0],
            vec![2, 1, 0, 2, 0, 0xaa],
            vec![3, 1, 0, 2, 0xaa],
        ] {
            assert!(!outgoing(&packet));
            assert!(!incoming(&mut packet));
        }
        let mut huge = vec![2, 1, 0, 0, 4];
        huge.extend([0; 1024]);
        assert!(!outgoing(&huge));
        assert!(incoming(&mut huge));
    }
}
