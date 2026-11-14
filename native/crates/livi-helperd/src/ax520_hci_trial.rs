// SPDX-FileCopyrightText: 2026 LIVI contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

use std::io;
use std::process::ExitCode;
use std::time::Duration;

fn duration(args: &[String]) -> io::Result<Duration> {
    if let [value] = args
        && let Ok(seconds @ 1..=90) = value.parse::<u64>()
    {
        return Ok(Duration::from_secs(seconds));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: --ax520-hci-trial <1..90 seconds>",
    ))
}

pub fn run(args: Vec<String>) -> ExitCode {
    let result = (|| {
        let within = duration(&args)?;
        // SAFETY: geteuid has no parameters or memory side effects.
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HCI trial requires root",
            ));
        }
        println!(
            "[ax520-hci-trial] metadata-only RAW_DEVICE; peer=127.0.0.1:15039; limit={}s",
            within.as_secs()
        );
        let result = livi_link_host::bt::trial::raw_probe(([127, 0, 0, 1], 15039).into(), within)?;
        println!(
            "[ax520-hci-trial] read_local_version=ok; virtual_index={}; hci_version={}; manufacturer={}; owned_controller_removed=true",
            result.index, result.version.hci_version, result.version.manufacturer
        );
        Ok::<_, io::Error>(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[ax520-hci-trial] {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_one_finite_duration_is_accepted() {
        for value in ["1", "45", "90"] {
            assert_eq!(
                duration(&[value.into()]).unwrap().as_secs(),
                value.parse::<u64>().unwrap()
            );
        }
        for args in [
            vec![],
            vec!["0".into()],
            vec!["91".into()],
            vec!["10".into(), "extra".into()],
            vec!["garbage".into()],
        ] {
            assert!(duration(&args).is_err());
        }
    }
}
