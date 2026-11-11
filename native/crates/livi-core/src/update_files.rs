// SPDX-FileCopyrightText: 2025-2026 Lasse Heitgres
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn staging_file(current: &Path, suffix: &str) -> io::Result<(PathBuf, File)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..32 {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let path = sibling(
            current,
            &format!(
                "{suffix}-{}-{}-{}",
                std::process::id(),
                time.as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ),
        );
        // create_new never follows a symlink or truncates another attempt.
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "Could not create a unique update staging file",
    ))
}

pub(super) fn replace_appimage(downloaded: &Path, current: &Path) -> io::Result<()> {
    let backup = sibling(current, ".old");
    let parent = File::open(current.parent().unwrap_or(Path::new(".")))?;
    let mut source = File::open(downloaded)?;
    let mut header = [0; 64];
    source.read_exact(&mut header)?;
    if &header[..4] != b"\x7fELF" || &header[8..11] != b"AI\x02" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Downloaded file is not a type-2 AppImage",
        ));
    }
    source.seek(SeekFrom::Start(0))?;
    let (staged, mut next) = staging_file(current, ".new")?;
    let result = (|| {
        io::copy(&mut source, &mut next)?;
        next.set_permissions(fs::Permissions::from_mode(0o755))?;
        next.sync_all()?;
        let mut previous = File::open(current)?;
        let (backup_staged, mut saved) = staging_file(current, ".old.new")?;
        let saved_result = (|| {
            io::copy(&mut previous, &mut saved)?;
            saved.set_permissions(previous.metadata()?.permissions())?;
            saved.sync_all()?;
            fs::rename(&backup_staged, &backup)?;
            parent.sync_all()?;
            fs::rename(&staged, current)?;
            parent.sync_all()
        })();
        if saved_result.is_err() {
            let _ = fs::remove_file(&backup_staged);
        }
        saved_result
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn in_directory(test: impl FnOnce(&Path)) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "livi-update-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        test(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    fn appimage() -> Vec<u8> {
        let mut bytes = vec![0; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[8..11].copy_from_slice(b"AI\x02");
        bytes
    }

    #[test]
    fn replacement_keeps_previous_image_for_manual_recovery() {
        in_directory(|dir| {
            let current = dir.join("LIVI.AppImage");
            let download = dir.join("download");
            fs::write(&current, b"previous image").unwrap();
            fs::write(&download, appimage()).unwrap();
            replace_appimage(&download, &current).unwrap();
            assert_eq!(fs::read(&current).unwrap(), appimage());
            assert_eq!(
                fs::read(dir.join("LIVI.AppImage.old")).unwrap(),
                b"previous image"
            );
        });
    }

    #[test]
    fn backup_failure_preserves_current_and_cleans_own_staging_file() {
        in_directory(|dir| {
            let current = dir.join("LIVI.AppImage");
            let download = dir.join("download");
            fs::write(&current, b"previous image").unwrap();
            fs::write(&download, appimage()).unwrap();
            fs::create_dir(dir.join("LIVI.AppImage.old")).unwrap();
            assert!(replace_appimage(&download, &current).is_err());
            assert_eq!(fs::read(&current).unwrap(), b"previous image");
            assert_eq!(fs::read_dir(dir).unwrap().count(), 3);
        });
    }

    #[test]
    fn existing_staging_symlink_is_not_followed() {
        in_directory(|dir| {
            let current = dir.join("LIVI.AppImage");
            let download = dir.join("download");
            let unrelated = dir.join("unrelated");
            fs::write(&current, b"previous image").unwrap();
            fs::write(&download, appimage()).unwrap();
            fs::write(&unrelated, b"keep me").unwrap();
            std::os::unix::fs::symlink(&unrelated, dir.join("LIVI.AppImage.new")).unwrap();
            std::os::unix::fs::symlink(&unrelated, dir.join("LIVI.AppImage.old.new")).unwrap();
            replace_appimage(&download, &current).unwrap();
            assert_eq!(fs::read(&current).unwrap(), appimage());
            assert_eq!(fs::read(&unrelated).unwrap(), b"keep me");
            assert!(dir.join("LIVI.AppImage.new").is_symlink());
            assert!(dir.join("LIVI.AppImage.old.new").is_symlink());
        });
    }

    #[test]
    fn orphan_staging_files_do_not_block_update_or_get_deleted() {
        in_directory(|dir| {
            let current = dir.join("LIVI.AppImage");
            let download = dir.join("download");
            fs::write(&current, b"previous image").unwrap();
            fs::write(&download, appimage()).unwrap();
            let orphans = [
                "LIVI.AppImage.new",
                "LIVI.AppImage.old.new",
                "LIVI.AppImage.new-123-456-0",
                "LIVI.AppImage.old.new-789-123-1",
            ];
            for name in orphans {
                fs::write(dir.join(name), b"orphaned attempt").unwrap();
            }
            replace_appimage(&download, &current).unwrap();
            assert_eq!(fs::read(&current).unwrap(), appimage());
            assert_eq!(
                fs::read(dir.join("LIVI.AppImage.old")).unwrap(),
                b"previous image"
            );
            for name in orphans {
                assert_eq!(fs::read(dir.join(name)).unwrap(), b"orphaned attempt");
            }
            assert_eq!(fs::read_dir(dir).unwrap().count(), 7);
        });
    }

    #[test]
    fn malformed_download_leaves_current_image_untouched() {
        in_directory(|dir| {
            let current = dir.join("LIVI.AppImage");
            let download = dir.join("download");
            fs::write(&current, b"previous image").unwrap();
            fs::write(&download, b"<html>server error</html>").unwrap();
            assert!(replace_appimage(&download, &current).is_err());
            assert_eq!(fs::read(&current).unwrap(), b"previous image");
        });
    }
}
