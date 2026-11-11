// SPDX-FileCopyrightText: 2026 LIVI contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

use std::path::Path;

#[derive(Clone, Copy)]
pub(super) struct Cpu {
    total: u64,
    idle: u64,
}
impl Cpu {
    pub(super) fn parse(text: &str) -> Option<Self> {
        let mut fields = text.lines().next()?.split_whitespace();
        if fields.next()? != "cpu" {
            return None;
        }
        // guest and guest_nice are already included in user and nice.
        let counters = fields
            .take(8)
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        if counters.len() < 4 {
            return None;
        }
        let total = counters
            .iter()
            .try_fold(0u64, |sum, n| sum.checked_add(*n))?;
        let idle = counters[3].checked_add(*counters.get(4).unwrap_or(&0))?;
        Some(Self { total, idle })
    }
    pub(super) fn usage(self, before: Self) -> Option<f64> {
        let total = self.total.checked_sub(before.total)?;
        let idle = self.idle.checked_sub(before.idle)?;
        if total == 0 {
            return None;
        }
        Some(100.0 * total.checked_sub(idle)? as f64 / total as f64)
    }
}
pub(super) fn memory(text: &str) -> (Option<u64>, Option<u64>) {
    let read = |key| {
        text.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next()? != key {
                return None;
            }
            let kb = fields.next()?.parse::<u64>().ok()?;
            if fields.next()? != "kB" {
                return None;
            }
            kb.checked_mul(1024)
        })
    };
    let total = read("MemTotal:");
    let available = read("MemAvailable:").filter(|n| total.is_some_and(|t| *n <= t));
    (total, available)
}
pub(super) fn gpu_percent(text: &str) -> Option<f64> {
    // Rockchip's devfreq load reports percentage or percentage@frequencyHz.
    let value = text.trim().split('@').next()?.parse::<f64>().ok()?;
    (value.is_finite() && (0.0..=100.0).contains(&value)).then_some(value)
}
pub(super) fn mount_path(path: &Path, mounts: &str) -> Option<String> {
    mounts
        .lines()
        .filter_map(|line| {
            let escaped = line.split_whitespace().nth(4)?;
            let decoded = escaped
                .replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\012", "\n")
                .replace("\\134", "\\");
            path.starts_with(&decoded).then_some(decoded)
        })
        .max_by_key(String::len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_uses_interval_and_does_not_count_guest_twice() {
        let before = Cpu::parse("cpu 100 0 50 800 50 0 0 0 20 0\ncpu0 1").unwrap();
        let after = Cpu::parse("cpu 130 0 60 850 60 0 0 0 40 0").unwrap();
        assert_eq!(after.usage(before), Some(40.0));
        assert_eq!(after.usage(after), None);
        assert_eq!(before.usage(after), None);
        assert!(Cpu::parse("cpu 1 broken 2 3").is_none());
    }

    #[test]
    fn memory_uses_available_including_reclaimable_cache() {
        assert_eq!(
            memory("MemTotal: 1000 kB\nMemFree: 50 kB\nMemAvailable: 400 kB\n"),
            (Some(1_024_000), Some(409_600))
        );
        assert_eq!(memory("MemTotal: 1000 kB\n"), (Some(1_024_000), None));
        assert_eq!(memory("MemTotal: broken kB\n"), (None, None));
    }

    #[test]
    fn gpu_load_accepts_only_documented_percentage_formats() {
        assert_eq!(gpu_percent("42"), Some(42.0));
        assert_eq!(gpu_percent("42@800000000Hz"), Some(42.0));
        assert_eq!(gpu_percent("101"), None);
        assert_eq!(gpu_percent("NaN"), None);
        assert_eq!(gpu_percent("busy 4 total 10"), None);
    }

    #[test]
    fn mount_path_decodes_spaces_and_chooses_longest_parent() {
        let mounts = "1 0 0:1 / / rw - ext4 /dev/a rw\n2 1 0:2 / /home/my\\040data rw - ext4 /dev/b rw\n3 1 0:3 / /home/my\\040database rw - ext4 /dev/c rw\n";
        assert_eq!(
            mount_path(std::path::Path::new("/home/my data/livi"), mounts),
            Some("/home/my data".into())
        );
        assert_eq!(
            mount_path(std::path::Path::new("/home/other"), mounts),
            Some("/".into())
        );
    }
}
