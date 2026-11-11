// SPDX-FileCopyrightText: 2026 LIVI contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::hub::Hub;
use livi_core_proto::state::{SystemStatistics, SystemTemperature};
#[path = "system_statistics/parse.rs"]
mod parse;

struct Collector {
    proc_root: PathBuf,
    sys_root: PathBuf,
    data_path: PathBuf,
    previous_cpu: Option<parse::Cpu>,
}
impl Collector {
    fn snapshot(&mut self) -> SystemStatistics {
        let cpu = fs::read_to_string(self.proc_root.join("stat"))
            .ok()
            .and_then(|s| parse::Cpu::parse(&s));
        let cpu_usage_percent = cpu
            .zip(self.previous_cpu)
            .and_then(|(now, before)| now.usage(before));
        self.previous_cpu = cpu;
        let (memory_total_bytes, memory_available_bytes) =
            parse::memory(&fs::read_to_string(self.proc_root.join("meminfo")).unwrap_or_default());
        let uptime_seconds = fs::read_to_string(self.proc_root.join("uptime"))
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
            .filter(|n| n.is_finite() && *n >= 0.0);
        let cpu_frequency_mhz = directories(&self.sys_root.join("devices/system/cpu/cpufreq"))
            .iter()
            .filter_map(|path| number(&path.join("scaling_cur_freq")))
            .reduce(f64::max)
            .map(|khz| khz / 1000.0);
        let temperatures = directories(&self.sys_root.join("class/thermal"))
            .into_iter()
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("thermal_zone"))
            })
            .filter_map(|path| {
                let celsius = fs::read_to_string(path.join("temp"))
                    .ok()?
                    .trim()
                    .parse::<f64>()
                    .ok()?
                    / 1000.0;
                if !celsius.is_finite() || !(-100.0..=250.0).contains(&celsius) {
                    return None;
                }
                let name = fs::read_to_string(path.join("type"))
                    .ok()
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| path.file_name().unwrap().to_string_lossy().into_owned());
                Some(SystemTemperature { name, celsius })
            })
            .collect();
        let gpu = directories(&self.sys_root.join("class/devfreq"))
            .into_iter()
            .find(|path| {
                path.file_name()
                    .is_some_and(|n| n.to_string_lossy().to_ascii_lowercase().contains("gpu"))
            });
        let gpu_usage_percent = gpu
            .as_ref()
            .and_then(|p| fs::read_to_string(p.join("load")).ok())
            .and_then(|s| parse::gpu_percent(&s));
        let gpu_frequency_mhz = gpu
            .as_ref()
            .and_then(|p| number(&p.join("cur_freq")))
            .map(|hz| hz / 1_000_000.0);
        let storage = storage(&self.data_path);
        let storage_path = storage
            .and_then(|_| fs::canonicalize(&self.data_path).ok())
            .map(|path| {
                fs::read_to_string(self.proc_root.join("self/mountinfo"))
                    .ok()
                    .and_then(|s| parse::mount_path(&path, &s))
                    .unwrap_or_else(|| path.to_string_lossy().into_owned())
            });
        SystemStatistics {
            cpu_usage_percent,
            cpu_frequency_mhz,
            gpu_usage_percent,
            gpu_frequency_mhz,
            memory_total_bytes,
            memory_available_bytes,
            storage_total_bytes: storage.map(|s| s.0),
            storage_available_bytes: storage.map(|s| s.1),
            storage_path,
            uptime_seconds,
            temperatures,
        }
    }
}

/// At most one filesystem scan runs at a time, off the async event loop.
pub(crate) async fn follow(hub: Arc<Hub>, data_path: PathBuf) {
    let mut collector = Collector {
        proc_root: PathBuf::from("/proc"),
        sys_root: PathBuf::from("/sys"),
        data_path,
        previous_cpu: None,
    };
    loop {
        let Ok((next, statistics)) = tokio::task::spawn_blocking(move || {
            let statistics = collector.snapshot();
            (collector, statistics)
        })
        .await
        else {
            return;
        };
        collector = next;
        hub.update(|state| state.system.statistics = statistics);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn directories(path: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(path)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    paths.sort();
    paths
}

fn number(path: &Path) -> Option<f64> {
    fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|n| n.is_finite() && *n >= 0.0)
}

// libc uses different integer widths on 32-bit and 64-bit Linux.
#[allow(clippy::unnecessary_cast)]
fn storage(path: &Path) -> Option<(u64, u64)> {
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut result = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is NUL terminated, and statvfs initializes result on success.
    if unsafe { libc::statvfs(path.as_ptr(), result.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: the successful call above initialized the complete statvfs structure.
    let result = unsafe { result.assume_init() };
    let block = result.f_frsize as u64;
    Some((
        (result.f_blocks as u64).checked_mul(block)?,
        (result.f_bavail as u64).checked_mul(block)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "livi-stats-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }
        fn write(&self, path: &str, text: &str) {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        fn collector(&self) -> Collector {
            Collector {
                proc_root: self.0.join("proc"),
                sys_root: self.0.join("sys"),
                data_path: self.0.clone(),
                previous_cpu: None,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn snapshot_reads_real_files_and_cpu_needs_two_samples() {
        let fixture = Fixture::new();
        fixture.write("proc/stat", "cpu 100 0 0 900 0 0 0 0");
        fixture.write("proc/meminfo", "MemTotal: 1000 kB\nMemAvailable: 400 kB\n");
        fixture.write("proc/uptime", "1234.56 9000.00");
        fixture.write("sys/class/thermal/thermal_zone0/type", "soc-thermal\n");
        fixture.write("sys/class/thermal/thermal_zone0/temp", "42500\n");
        fixture.write(
            "sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq",
            "1800000\n",
        );
        fixture.write("sys/class/devfreq/fb000000.gpu/load", "37@800000000Hz\n");
        fixture.write("sys/class/devfreq/fb000000.gpu/cur_freq", "800000000\n");
        let mut collector = fixture.collector();
        let first = collector.snapshot();
        assert_eq!(first.cpu_usage_percent, None);
        assert_eq!(first.memory_available_bytes, Some(409600));
        assert_eq!(first.uptime_seconds, Some(1234.56));
        assert_eq!(first.cpu_frequency_mhz, Some(1800.0));
        assert_eq!(first.gpu_usage_percent, Some(37.0));
        assert_eq!(first.gpu_frequency_mhz, Some(800.0));
        assert_eq!(first.temperatures[0].name, "soc-thermal");
        assert_eq!(first.temperatures[0].celsius, 42.5);
        assert!(first.storage_total_bytes.is_some_and(|n| n > 0));
        fixture.write("proc/stat", "cpu 125 0 0 975 0 0 0 0");
        assert_eq!(collector.snapshot().cpu_usage_percent, Some(25.0));
    }

    #[test]
    fn missing_or_invalid_readings_are_unavailable() {
        let fixture = Fixture::new();
        fixture.write("proc/uptime", "NaN 0");
        fixture.write("sys/class/thermal/thermal_zone0/temp", "broken");
        fixture.write("sys/class/devfreq/dmc/load", "60");
        let mut collector = fixture.collector();
        collector.data_path = fixture.0.join("missing");
        assert_eq!(collector.snapshot(), SystemStatistics::default());
    }
}
