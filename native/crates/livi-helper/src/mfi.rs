// SPDX-FileCopyrightText: 2025-2026 Lasse Heitgres
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use iap2_mfi::file::{CERTIFICATE_FILE, IDENTITY_FILE};
use iap2_mfi::{AuthCoprocessor, FileCoprocessor, NcmCoprocessor};

pub type Coprocessor = Box<dyn AuthCoprocessor + Send>;

fn endpoint_address(endpoint: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = endpoint.trim().parse().map_err(|_| {
        "MFi endpoint must be 127.0.0.1:PORT or [::1]:PORT (literal address, nonzero port)"
            .to_string()
    })?;
    if addr.port() == 0
        || !matches!(addr.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST)
            && !matches!(addr.ip(), IpAddr::V6(ip) if ip == Ipv6Addr::LOCALHOST)
    {
        return Err("MFi endpoint must use 127.0.0.1 or ::1 and a nonzero port".into());
    }
    Ok(addr)
}

/// An explicit endpoint takes precedence and never falls back to another identity.
pub fn select(
    endpoint: &str,
    local: impl FnOnce() -> Option<Coprocessor>,
) -> Result<Option<Coprocessor>, String> {
    if endpoint.is_empty() {
        return Ok(local());
    }
    let addr = endpoint_address(endpoint)?;
    let mut chip = NcmCoprocessor::new(&addr.to_string());
    // NcmCoprocessor bounds connect/read/write time and retries once on I/O failure.
    // This is a protocol availability check, not proof of successful authentication.
    let major = chip.protocol_major().map_err(|e| {
        format!("MFi endpoint {addr} unavailable: {e}; no other authentication provider selected")
    })?;
    if !matches!(major, 2 | 3) {
        return Err(format!(
            "MFi endpoint {addr} returned unsupported protocol major {major}"
        ));
    }
    println!(
        "[helper] MFi endpoint {addr}: protocol major {major} (authentication not yet tested)"
    );
    Ok(Some(Box::new(chip)))
}

pub fn open_in(dir: &Path) -> Option<FileCoprocessor> {
    if !dir.join(CERTIFICATE_FILE).exists() && !dir.join(IDENTITY_FILE).exists() {
        return None;
    }
    match FileCoprocessor::open(dir) {
        Ok(files) => {
            println!("[helper] MFi from the imported files in {}", dir.display());
            Some(files)
        }
        Err(e) => {
            println!(
                "[helper] MFi files in {} are not usable: {e}",
                dir.display()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn only_explicit_loopback_addresses_with_a_port_are_allowed() {
        for endpoint in ["127.0.0.1:15000", "[::1]:5000"] {
            assert!(endpoint_address(endpoint).is_ok(), "{endpoint}");
        }
        for endpoint in [
            "",
            " ",
            "localhost:5000",
            "127.0.0.1:0",
            "127.0.0.2:5000",
            "192.168.50.100:5000",
            "0.0.0.0:5000",
            "[::]:5000",
            "[::ffff:127.0.0.1]:5000",
            "http://127.0.0.1:5000",
            "127.0.0.1",
        ] {
            assert!(endpoint_address(endpoint).is_err(), "{endpoint}");
        }
    }

    #[test]
    fn an_unconfigured_endpoint_keeps_existing_provider_selection() {
        let called = Cell::new(false);
        assert!(
            select("", || {
                called.set(true);
                None
            })
            .unwrap()
            .is_none()
        );
        assert!(called.get());
    }

    #[test]
    fn an_invalid_or_unavailable_endpoint_never_falls_back() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        drop(listener);
        for endpoint in ["localhost:5000", &endpoint] {
            assert!(select(endpoint, || panic!("must not select another identity")).is_err());
        }
    }

    fn protocol_peer(major: u8) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let task = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut request = [0];
            socket.read_exact(&mut request).unwrap();
            assert_eq!(request, [iap2_mfi::server::OP_PROTOCOL_MAJOR]);
            socket
                .write_all(&[iap2_mfi::server::STATUS_OK, 0, 1, major])
                .unwrap();
        });
        (endpoint, task)
    }

    #[test]
    fn availability_checks_protocol_without_requesting_identity_or_signatures() {
        for major in [2, 3] {
            let (endpoint, peer) = protocol_peer(major);
            let mut chip = select(&endpoint, || panic!("explicit endpoint takes precedence"))
                .unwrap()
                .unwrap();
            peer.join().unwrap();
            assert_eq!(chip.protocol_major().unwrap(), major);
        }
    }

    #[test]
    fn an_unknown_protocol_never_selects_another_identity() {
        let (endpoint, peer) = protocol_peer(4);
        let error = select(&endpoint, || panic!("must not fall back"))
            .err()
            .unwrap();
        peer.join().unwrap();
        assert!(error.contains("unsupported protocol major 4"));
    }

    #[test]
    fn an_empty_folder_leaves_the_chip_in_charge() {
        let dir = std::env::temp_dir().join(format!("livi-helper-mfi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(open_in(&dir).is_none());
        std::fs::write(dir.join(IDENTITY_FILE), b"broken").unwrap();
        assert!(open_in(&dir).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
