// SPDX-FileCopyrightText: 2025-2026 Lasse Heitgres
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

use std::fs;
use std::path::{Path, PathBuf};

use nusb::MaybeFuture;

use crate::usb_pipe::await_carplay_configs;
use crate::{APPLE_VID, CP_CONFIG, DEFAULT_CONFIG};

const SYSFS_USB: &str = "/sys/bus/usb/devices";

#[derive(Debug, Clone)]
pub struct IPhoneDev {
    pub serial: String,
    pub sysfs: PathBuf,
    pub bus: u8,
    pub address: u8,
    pub num_configs: u8,
    pub config_value: Option<u8>,
}

fn read_trim(path: &Path, name: &str) -> Option<String> {
    fs::read_to_string(path.join(name))
        .ok()
        .map(|s| s.trim().to_string())
}

// Apple USB IDs alone do not establish an iPhone: some adapters expose them
// alongside ADB. Check all cached configurations before phone setup requests.
fn has_adb_interface(mut descriptors: &[u8]) -> Option<bool> {
    if descriptors.len() < 18 || descriptors[..2] != [18, 1] {
        return None;
    }
    let expected_configs = usize::from(descriptors[17]);
    descriptors = &descriptors[18..];
    let mut configs = 0;
    let mut has_interface = false;
    let mut found = false;
    // Linux's sysfs ABI says to walk bLength, not advertised wTotalLength:
    // cached configurations can be shorter than the device advertised.
    while !descriptors.is_empty() {
        if descriptors.len() < 2 {
            return None;
        }
        let length = usize::from(descriptors[0]);
        if length < 2 || length > descriptors.len() {
            return None;
        }
        match descriptors[1] {
            2 => {
                if length < 9 || (configs != 0 && !has_interface) {
                    return None;
                }
                configs += 1;
                has_interface = false;
            }
            4 => {
                if configs == 0 || length < 9 {
                    return None;
                }
                has_interface = true;
                found |= descriptors[5..8] == [0xff, 0x42, 0x01];
            }
            _ if configs == 0 => return None,
            _ => {}
        }
        descriptors = &descriptors[length..];
    }
    (configs == expected_configs && has_interface).then_some(found)
}

pub fn find_iphones() -> Vec<IPhoneDev> {
    find_iphones_in(Path::new(SYSFS_USB))
}

fn find_iphones_in(root: &Path) -> Vec<IPhoneDev> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return out;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if read_trim(&path, "idVendor").as_deref() != Some("05ac") {
            continue;
        }
        let Ok(descriptors) = fs::read(path.join("descriptors")) else {
            continue;
        };
        if has_adb_interface(&descriptors) != Some(false) {
            continue;
        }
        let Some(serial) = read_trim(&path, "serial").filter(|s| !s.is_empty()) else {
            continue;
        };
        let bus = read_trim(&path, "busnum")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let address = read_trim(&path, "devnum")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let num_configs = read_trim(&path, "bNumConfigurations")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let config_value = read_trim(&path, "bConfigurationValue").and_then(|s| s.parse().ok());
        out.push(IPhoneDev {
            serial,
            sysfs: path,
            bus,
            address,
            num_configs,
            config_value,
        });
    }
    let _ = APPLE_VID;
    out
}

fn find_by_serial(serial: &str) -> Option<IPhoneDev> {
    find_iphones().into_iter().find(|d| d.serial == serial)
}

pub fn ensure_carplay_config(serial: &str) -> Result<IPhoneDev, String> {
    let dev = find_by_serial(serial).ok_or_else(|| format!("iphone {serial} not found"))?;

    if dev.num_configs < CP_CONFIG {
        request_carplay_configs(&dev)?;
        await_carplay_configs(serial, || {
            find_by_serial(serial).is_some_and(|d| d.num_configs >= CP_CONFIG)
        })?;
    }

    let dev = find_by_serial(serial).ok_or("iphone gone after config request")?;
    if dev.config_value != Some(CP_CONFIG) {
        fs::write(dev.sysfs.join("bConfigurationValue"), CP_CONFIG.to_string())
            .map_err(|e| format!("set config {CP_CONFIG}: {e}"))?;
    }
    find_by_serial(serial).ok_or_else(|| "iphone gone after config select".to_string())
}

pub fn restore_all_default_config() {
    for dev in find_iphones() {
        if dev.config_value == Some(CP_CONFIG) {
            let _ = fs::write(
                dev.sysfs.join("bConfigurationValue"),
                DEFAULT_CONFIG.to_string(),
            );
        }
    }
}

pub fn restore_default_config(serial: &str) {
    if let Some(dev) = find_by_serial(serial) {
        let _ = fs::write(
            dev.sysfs.join("bConfigurationValue"),
            DEFAULT_CONFIG.to_string(),
        );
    }
}

pub fn reset(serial: &str) -> Result<(), String> {
    let dev = find_by_serial(serial).ok_or_else(|| format!("{serial} is not on the bus"))?;
    open_by_address(dev.bus, dev.address)?
        .reset()
        .wait()
        .map_err(|e| format!("usb reset: {e}"))
}

fn request_carplay_configs(dev: &IPhoneDev) -> Result<(), String> {
    crate::usb_pipe::request_carplay_configs(&open_by_address(dev.bus, dev.address)?)
}

pub fn open(serial: &str) -> Result<nusb::Device, String> {
    let dev = find_by_serial(serial).ok_or_else(|| format!("iphone {serial} not found"))?;
    open_by_address(dev.bus, dev.address)
}

pub fn open_by_address(bus: u8, address: u8) -> Result<nusb::Device, String> {
    nusb::list_devices()
        .wait()
        .map_err(|e| e.to_string())?
        .find(|d| d.busnum() == bus && d.device_address() == address)
        .ok_or_else(|| format!("usb device {bus}/{address} not found"))?
        .open()
        .wait()
        .map_err(|e| format!("open usb: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct UsbFixture(PathBuf);
    impl UsbFixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "livi-usb-enumeration-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn device(&self, name: &str, serial: &str, descriptors: Option<&[u8]>) {
            let path = self.0.join(name);
            fs::create_dir(&path).unwrap();
            for (attribute, value) in [
                ("idVendor", "05ac"),
                ("serial", serial),
                ("busnum", "4"),
                ("devnum", "2"),
                ("bNumConfigurations", "4"),
                ("bConfigurationValue", "1"),
            ] {
                fs::write(path.join(attribute), format!("{value}\n")).unwrap();
            }
            if let Some(bytes) = descriptors {
                if let Some(count) = bytes.get(17) {
                    fs::write(path.join("bNumConfigurations"), count.to_string()).unwrap();
                }
                fs::write(path.join("descriptors"), bytes).unwrap();
            }
        }
        fn phones(&self) -> Vec<String> {
            find_iphones_in(&self.0)
                .into_iter()
                .map(|d| d.serial)
                .collect()
        }
    }
    impl Drop for UsbFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn descriptor_blob(interfaces: &[[u8; 3]]) -> Vec<u8> {
        let mut bytes = vec![
            18, 1, 0, 2, 0, 0, 0, 64, 0xac, 0x05, 0xa8, 0x12, 0, 1, 1, 2, 3, 1,
        ];
        bytes[17] = interfaces.len() as u8;
        for (index, class) in interfaces.iter().enumerate() {
            bytes.extend_from_slice(&[9, 2, 18, 0, 1, (index + 1) as u8, 0, 0x80, 250]);
            bytes.extend_from_slice(&[9, 4, 0, 0, 0, class[0], class[1], class[2], 0]);
        }
        bytes
    }

    #[test]
    fn adb_gadget_is_excluded_while_real_phone_is_retained() {
        // A missing ADB guard would send phone setup requests to this bridge.
        let usb = UsbFixture::new();
        usb.device("4-1", "BRIDGE", Some(&descriptor_blob(&[[0xff, 0x42, 1]])));
        usb.device("5-1", "PHONE", Some(&descriptor_blob(&[[6, 1, 1]])));
        assert_eq!(usb.phones(), ["PHONE"]);
    }
    #[test]
    fn adb_in_an_inactive_configuration_is_still_excluded() {
        // Looking only at active interface directories would miss the ADB role.
        let usb = UsbFixture::new();
        usb.device(
            "4-1",
            "BRIDGE",
            Some(&descriptor_blob(&[[6, 1, 1], [0xff, 0x42, 1]])),
        );
        assert!(usb.phones().is_empty());
    }
    #[test]
    fn other_vendor_specific_interfaces_remain_eligible() {
        // Matching only vendor class/subclass would incorrectly hide a phone.
        let usb = UsbFixture::new();
        usb.device("4-1", "PHONE", Some(&descriptor_blob(&[[0xff, 0x42, 2]])));
        assert_eq!(usb.phones(), ["PHONE"]);
    }
    #[test]
    fn truncated_descriptors_wait_for_a_later_scan() {
        // A partial enumeration must not cause a premature USB control request.
        let usb = UsbFixture::new();
        let mut bytes = descriptor_blob(&[[6, 1, 1]]);
        bytes.pop();
        usb.device("4-1", "PARTIAL", Some(&bytes));
        assert!(usb.phones().is_empty());
    }
    #[test]
    fn complete_descriptor_boundary_does_not_hide_a_missing_adb_tail() {
        // The device still advertises two configurations; the ADB one is missing.
        let usb = UsbFixture::new();
        let mut bytes = descriptor_blob(&[[6, 1, 1], [0xff, 0x42, 1]]);
        bytes.truncate(36);
        usb.device("4-1", "PARTIAL", Some(&bytes));
        assert!(usb.phones().is_empty());
    }
    #[test]
    fn device_descriptor_without_its_configurations_waits() {
        let usb = UsbFixture::new();
        let mut bytes = descriptor_blob(&[[0xff, 0x42, 1]]);
        bytes.truncate(18);
        usb.device("4-1", "PARTIAL", Some(&bytes));
        assert!(usb.phones().is_empty());
    }
    #[test]
    fn configuration_without_an_interface_is_not_a_phone() {
        let usb = UsbFixture::new();
        let mut bytes = descriptor_blob(&[[0xff, 0x42, 1]]);
        bytes.truncate(27);
        usb.device("4-1", "PARTIAL", Some(&bytes));
        assert!(usb.phones().is_empty());
    }
    #[test]
    fn cached_configuration_may_be_shorter_than_advertised() {
        // Linux documents wTotalLength as untrustworthy in this sysfs file.
        let usb = UsbFixture::new();
        let mut bytes = descriptor_blob(&[[6, 1, 1]]);
        bytes[20..22].copy_from_slice(&65535u16.to_le_bytes());
        usb.device("4-1", "PHONE", Some(&bytes));
        assert_eq!(usb.phones(), ["PHONE"]);
    }
    #[test]
    fn cached_interface_count_may_differ_from_advertised() {
        // The kernel may adjust parsed counts while retaining the raw bytes.
        let usb = UsbFixture::new();
        let mut bytes = descriptor_blob(&[[6, 1, 1]]);
        bytes[22] = 2;
        usb.device("4-1", "PHONE", Some(&bytes));
        assert_eq!(usb.phones(), ["PHONE"]);
    }
    #[test]
    fn unreadable_descriptors_wait_for_a_later_scan() {
        let usb = UsbFixture::new();
        usb.device("4-1", "PARTIAL", None);
        assert!(usb.phones().is_empty());
    }
    #[test]
    fn adb_bytes_outside_an_interface_descriptor_are_ignored() {
        // A byte-pattern search would incorrectly exclude a device descriptor.
        let usb = UsbFixture::new();
        let mut bytes = descriptor_blob(&[[6, 1, 1]]);
        bytes[4..7].copy_from_slice(&[0xff, 0x42, 1]);
        usb.device("4-1", "PHONE", Some(&bytes));
        assert_eq!(usb.phones(), ["PHONE"]);
    }
    #[test]
    fn zero_length_descriptor_does_not_loop_or_accept() {
        let usb = UsbFixture::new();
        let mut bytes = descriptor_blob(&[[6, 1, 1]]);
        bytes[18] = 0;
        usb.device("4-1", "PARTIAL", Some(&bytes));
        assert!(usb.phones().is_empty());
    }
}
