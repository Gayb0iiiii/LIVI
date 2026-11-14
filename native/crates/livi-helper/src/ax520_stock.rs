// SPDX-FileCopyrightText: 2026 LIVI contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::net::Ipv6Addr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};

use livi_core_proto::ax520::{AP_PROFILE, INTERFACE};
use livi_runtime::bringup::CpConfig;
use livi_runtime::ident::Identity;
use livi_wifi::{Band, Channel, OnAir, Security};

const MAX_PROFILE_BYTES: u64 = 4096;
static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);

struct Active {
    profile: Profile,
    transport: Weak<livi_link_host::external_net::Handle>,
}

#[derive(Clone)]
struct Profile {
    ssid: String,
    bssid: String,
    channel: Channel,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "AX520 AP profile is invalid")
}

impl Profile {
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let object = value.as_object().ok_or_else(invalid)?;
        let fields = ["ssid", "bssid", "frequency", "security"];
        if object.len() != fields.len() || object.keys().any(|k| !fields.contains(&k.as_str())) {
            return Err(invalid());
        }
        let text = |field: &str| object[field].as_str().ok_or_else(invalid);
        let ssid = text("ssid")?;
        if ssid.is_empty() || ssid.len() > 32 || ssid.chars().any(char::is_control) {
            return Err(invalid());
        }
        let bssid = text("bssid")?;
        let parts: Vec<_> = bssid.split(':').collect();
        if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
            return Err(invalid());
        }
        let address: Vec<_> = parts
            .iter()
            .map(|p| u8::from_str_radix(p, 16).map_err(|_| invalid()))
            .collect::<io::Result<_>>()?;
        if address[0] & 1 != 0 || address.iter().all(|b| *b == 0) {
            return Err(invalid());
        }
        let frequency = object["frequency"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(invalid)?;
        let channel = Channel::of_freq(frequency)
            .filter(|c| c.number > 0 && c.freq_mhz() == frequency && c.band != Band::Ghz6)
            .ok_or_else(invalid)?;
        if text("security")? != "wpa2" {
            return Err(invalid());
        }
        Ok(Self {
            ssid: ssid.into(),
            bssid: bssid.to_ascii_uppercase(),
            channel,
        })
    }

    fn load(path: &Path) -> io::Result<Self> {
        // O_NONBLOCK also prevents an incorrectly supplied FIFO from hanging startup.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| io::Error::new(e.kind(), "AX520 AP profile could not be opened"))?;
        let metadata = file.metadata().map_err(|_| invalid())?;
        if !metadata.is_file() || metadata.len() > MAX_PROFILE_BYTES {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take(MAX_PROFILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if bytes.len() as u64 > MAX_PROFILE_BYTES {
            return Err(invalid());
        }
        Self::parse(&bytes)
    }

    fn apply(&self, identity: &mut Identity, cp: &mut CpConfig) {
        identity.ssid = self.ssid.clone();
        cp.ssid = self.ssid.clone();
        cp.wifi_iface = INTERFACE.into();
        cp.channel = self.channel;
        cp.ap_mac = Some(self.bssid.clone());
        cp.ap_on_air = Some(on_air);
    }

    fn on_air(&self) -> OnAir {
        OnAir {
            ssid: self.ssid.clone(),
            channel: self.channel,
            security: Security::Wpa2,
        }
    }
}

/// Load only explicit metadata for an AP already managed by the stock firmware.
/// Failure leaves wireless unavailable while the existing wired path can continue.
pub fn configure(
    mfi: &Path,
    passphrase: &str,
    identity: &mut Identity,
    cp: &mut CpConfig,
) -> io::Result<()> {
    let mut active = ACTIVE.lock().unwrap();
    *active = None;
    cp.wifi_iface = INTERFACE.into();
    cp.ap_on_air = Some(on_air);
    cp.ap_mac = None;
    cp.ssid.clear();
    identity.ssid.clear();
    if !(8..=63).contains(&passphrase.len())
        || !passphrase.is_ascii()
        || passphrase.bytes().any(|b| b.is_ascii_control())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AX520 AP requires its configured WPA2 passphrase",
        ));
    }
    let path = mfi.parent().ok_or_else(invalid)?.join(AP_PROFILE);
    let profile = Profile::load(&path)?;
    profile.apply(identity, cp);
    *active = Some(Active {
        profile,
        transport: Weak::new(),
    });
    Ok(())
}

pub fn configured() -> bool {
    ACTIVE.lock().unwrap().is_some()
}

pub fn bind_transport(transport: &Arc<livi_link_host::external_net::Handle>) {
    if let Some(active) = ACTIVE.lock().unwrap().as_mut() {
        active.transport = Arc::downgrade(transport);
    }
}

fn transport_ready_in(owned: bool, net: &Path, inet6: &Path) -> bool {
    owned && ready_in(net, inet6)
}

fn ready_in(net: &Path, inet6: &Path) -> bool {
    let flags = fs::read_to_string(net.join("flags"))
        .ok()
        .and_then(|v| u32::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    if flags & 1 == 0 || !fs::read_to_string(net.join("carrier")).is_ok_and(|v| v.trim() == "1") {
        return false;
    }
    fs::read_to_string(inet6).is_ok_and(|text| {
        text.lines().any(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() != 6 || parts[5] != INTERFACE || parts[3] != "20" {
                return false;
            }
            let usable =
                u32::from_str_radix(parts[4], 16).is_ok_and(|f| f & (0x40 | 0x08 | 0x04) == 0);
            usable
                && u128::from_str_radix(parts[0], 16)
                    .is_ok_and(|v| Ipv6Addr::from(v).is_unicast_link_local())
        })
    })
}

/// Report saved AP metadata only while the external TAP transport is ready.
pub fn on_air() -> Option<OnAir> {
    let (profile, transport) = {
        let active = ACTIVE.lock().unwrap();
        let active = active.as_ref()?;
        (active.profile.clone(), active.transport.upgrade()?)
    };
    transport_ready_in(
        transport.is_ready(),
        Path::new("/sys/class/net/ax520cp0"),
        Path::new("/proc/net/if_inet6"),
    )
    .then(|| profile.on_air())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const PROFILE: &str =
        r#"{"ssid":"Fixture AP","bssid":"02:10:20:30:40:50","frequency":5220,"security":"wpa2"}"#;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "livi-stock-ap-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn stock_ap_metadata_does_not_replace_the_car_name_or_authentication_endpoint() {
        let profile = Profile::parse(PROFILE.as_bytes()).unwrap();
        let mut start = livi_core_proto::helper::HelperStart {
            settings: Default::default(),
            device_id: String::new(),
            public_key: String::new(),
            pairing_id: String::new(),
            airplay_port: Some(7000),
            mirror: None,
        };
        start.settings.car_name = "Fixture Vehicle".into();
        start.settings.wifi_iface = "ax520-stock".into();
        start.settings.passphrase = "fixture-passphrase".into();
        start.settings.mfi_endpoint = "127.0.0.1:15000".into();
        let (mut identity, mut cp) = crate::carplay(&start, livi_runtime::ident::Transport::Wired);
        profile.apply(&mut identity, &mut cp);
        assert_eq!(identity.name, "Fixture Vehicle");
        assert_eq!(identity.ssid, "Fixture AP");
        assert_eq!(cp.ssid, "Fixture AP");
        assert_eq!(cp.ap_mac.as_deref(), Some("02:10:20:30:40:50"));
        assert_eq!(cp.wifi_iface, "ax520cp0");
        assert_eq!(cp.channel.freq_mhz(), 5220);
        assert_eq!(cp.passphrase, "fixture-passphrase");
        assert!(cp.ap_on_air.is_some());
        assert_eq!(start.settings.mfi_endpoint, "127.0.0.1:15000");
    }

    #[test]
    fn stock_ap_rejects_invalid_or_unverified_metadata_without_echoing_it() {
        for (field, value) in [
            ("ssid", serde_json::json!("")),
            ("ssid", serde_json::json!("x".repeat(33))),
            ("ssid", serde_json::json!("é".repeat(17))),
            ("ssid", serde_json::json!("bad\u{0}name")),
            ("bssid", serde_json::json!("01:10:20:30:40:50")),
            ("bssid", serde_json::json!("00:00:00:00:00:00")),
            ("bssid", serde_json::json!("not-a-bssid")),
            ("frequency", serde_json::json!(5221)),
            ("frequency", serde_json::json!(0)),
            ("frequency", serde_json::json!("5220")),
            ("security", serde_json::json!("open")),
            ("security", serde_json::json!("wpa3")),
            ("password", serde_json::json!("must-not-be-in-profile")),
        ] {
            let mut bad: serde_json::Value = serde_json::from_str(PROFILE).unwrap();
            bad[field] = value;
            let error = Profile::parse(&serde_json::to_vec(&bad).unwrap())
                .err()
                .expect(field);
            assert!(!error.to_string().contains("Fixture"));
            assert!(!error.to_string().contains("must-not-be-in-profile"));
        }
    }

    #[test]
    fn stock_ap_load_accepts_only_a_small_regular_file_and_never_follows_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new();
        let path = dir.0.join("ax520-ap.json");
        fs::write(&path, PROFILE).unwrap();
        assert!(Profile::load(&path).is_ok());
        fs::write(&path, vec![b' '; 4097]).unwrap();
        assert!(Profile::load(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::write(dir.0.join("other.json"), PROFILE).unwrap();
        symlink(dir.0.join("other.json"), &path).unwrap();
        assert!(Profile::load(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(Profile::load(&path).is_err());
    }

    #[test]
    fn stock_ap_missing_profile_clears_wireless_state_without_replacing_wired_identity() {
        let dir = TempDir::new();
        let mfi = dir.0.join("mfi");
        let profile = dir.0.join("ax520-ap.json");
        fs::write(&profile, PROFILE).unwrap();
        let start = livi_core_proto::helper::HelperStart {
            settings: livi_core_proto::helper::HelperSettings {
                car_name: "Fixture Vehicle".into(),
                passphrase: "fixture-passphrase".into(),
                ..Default::default()
            },
            device_id: "02:10:20:30:40:99".into(),
            public_key: String::new(),
            pairing_id: String::new(),
            airplay_port: Some(7000),
            mirror: None,
        };
        let (mut identity, mut cp) = crate::carplay(&start, livi_runtime::ident::Transport::Wired);
        configure(&mfi, &start.settings.passphrase, &mut identity, &mut cp).unwrap();
        assert!(configured());
        fs::remove_file(&profile).unwrap();
        assert!(configure(&mfi, &start.settings.passphrase, &mut identity, &mut cp).is_err());
        assert!(!configured());
        assert!(on_air().is_none());
        assert!(cp.ssid.is_empty());
        assert!(cp.ap_mac.is_none());
        assert_eq!(cp.wifi_iface, "ax520cp0");
        assert_eq!(identity.name, "Fixture Vehicle");
        assert_eq!(cp.device_id.as_deref(), Some("02:10:20:30:40:99"));
        assert!(matches!(
            cp.transport,
            livi_runtime::ident::Transport::Wired
        ));
    }

    #[test]
    fn stock_ap_readiness_requires_up_carrier_and_usable_link_local_on_the_exact_tap() {
        let dir = TempDir::new();
        let net = dir.0.join("ax520cp0");
        fs::create_dir(&net).unwrap();
        fs::write(net.join("flags"), "0x1003\n").unwrap();
        fs::write(net.join("carrier"), "1\n").unwrap();
        let inet6 = dir.0.join("if_inet6");
        let live = "fe800000000000000000000000000001 04 40 20 80 ax520cp0\n";
        fs::write(&inet6, live).unwrap();
        assert!(ready_in(&net, &inet6));
        assert!(
            !transport_ready_in(false, &net, &inet6),
            "an existing foreign TAP is never used"
        );
        assert!(transport_ready_in(true, &net, &inet6));
        fs::write(&inet6, live.replace("20 80", "20 c0")).unwrap();
        assert!(!ready_in(&net, &inet6), "tentative addresses are not ready");
        fs::write(&inet6, live.replace("ax520cp0", "eth0")).unwrap();
        assert!(!ready_in(&net, &inet6));
        fs::write(&inet6, live).unwrap();
        fs::write(net.join("carrier"), "0\n").unwrap();
        assert!(!ready_in(&net, &inet6));
        fs::write(net.join("carrier"), "1\n").unwrap();
        fs::write(net.join("flags"), "0x1002\n").unwrap();
        assert!(!ready_in(&net, &inet6));
    }
}
