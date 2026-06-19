//! The Linux *immutable inode attribute* (`chattr +i`), implemented directly via
//! the `FS_IOC_GETFLAGS`/`FS_IOC_SETFLAGS` ioctls — **no `chattr` subprocess and
//! no `nix` dependency**.
//!
//! Setting the immutable bit on a file means that, until the bit is cleared, the
//! file cannot be modified, renamed, deleted, or hard-linked — *even by root*,
//! who must first clear the bit (which requires `CAP_LINUX_IMMUTABLE`). This is
//! the OS-supported mechanism the installer uses to stop an unprivileged user
//! from tampering with the agent binary and its systemd units, while remaining
//! fully reversible by an administrator (see [`super::install::uninstall`]).
//!
//! ## Design: a pure core + a thin syscall shell
//!
//! The flag arithmetic ([`apply_immutable`]/[`is_immutable`]) is a pure function
//! of a flags word and is unit-tested in CI without any privilege. The syscall
//! shell ([`set_immutable`]/[`check_immutable`]) performs the `ioctl`s and is
//! exercised only at runtime on a real host (it needs root for `SETFLAGS`); it is
//! never invoked by a `#[test]`.

use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// The inode *immutable* flag from `<linux/fs.h>`.
///
/// The `libc` crate exposes the `FS_IOC_GETFLAGS`/`FS_IOC_SETFLAGS` ioctl request
/// numbers but **not** the individual `FS_*_FL` flag values, so we define the one
/// we need here. Verified against `/usr/include/linux/fs.h:359`
/// (`#define FS_IMMUTABLE_FL 0x00000010`) and corroborated by e2fsprogs'
/// `EXT2_IMMUTABLE_FL = 0x00000010`.
///
/// The flags word passed through the ioctl is a `long` (the kernel header
/// defines `FS_IOC_GETFLAGS` as `_IOR('f', 1, long)`), so this is typed
/// [`libc::c_long`] to match the buffer it is OR-ed into.
pub const FS_IMMUTABLE_FL: libc::c_long = 0x0000_0010;

/// Pure flag transform: return `flags` with the immutable bit set or cleared.
///
/// Only the immutable bit is touched; every other inode flag in the word is
/// preserved, which is what makes [`set_immutable`]'s read-modify-write safe.
#[must_use]
pub fn apply_immutable(flags: libc::c_long, immutable: bool) -> libc::c_long {
    if immutable {
        flags | FS_IMMUTABLE_FL
    } else {
        flags & !FS_IMMUTABLE_FL
    }
}

/// Pure predicate: is the immutable bit set in this flags word?
#[must_use]
pub fn is_immutable(flags: libc::c_long) -> bool {
    flags & FS_IMMUTABLE_FL != 0
}

/// Open `path` `O_RDONLY | O_CLOEXEC` and return the owned file.
///
/// `FS_IOC_GETFLAGS`/`SETFLAGS` operate on any open fd referring to the inode
/// (regular file *or* directory); read-only is sufficient. `O_CLOEXEC` avoids
/// leaking the descriptor across an exec.
fn open_ro(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
}

/// Read the inode flags word via `FS_IOC_GETFLAGS`.
fn get_flags(path: &Path) -> io::Result<libc::c_long> {
    let file = open_ro(path)?;
    let mut flags: libc::c_long = 0;
    // SAFETY: `file` owns a valid fd for the duration of the call. FS_IOC_GETFLAGS
    // is `_IOR('f', 1, long)`, so the kernel writes a `long` through the pointer;
    // `flags` is a live `c_long` of exactly that size. We check the return value
    // and surface errno via `last_os_error` on failure.
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags)
}

/// Write the inode flags word via `FS_IOC_SETFLAGS`.
///
/// Requires `CAP_LINUX_IMMUTABLE` (i.e. root) to set/clear the immutable bit;
/// returns `EPERM` otherwise, and `ENOTTY` on filesystems without flag support.
fn set_flags(path: &Path, flags: libc::c_long) -> io::Result<()> {
    let file = open_ro(path)?;
    // SAFETY: `file` owns a valid fd. FS_IOC_SETFLAGS is `_IOW('f', 2, long)`, so
    // the kernel reads a `long` through the pointer; we pass the address of a live
    // `c_long`. The return value is checked and errno surfaced on failure.
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_SETFLAGS, &flags) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set or clear the immutable attribute on `path` (read-modify-write).
///
/// The current flags are read first so that only the immutable bit is changed and
/// no other inode flags are clobbered. If the bit is already in the desired
/// state, no write is attempted (idempotent). Needs root to actually flip the
/// bit; on lesser privilege the underlying `SETFLAGS` returns `EPERM`.
pub fn set_immutable(path: &Path, immutable: bool) -> io::Result<()> {
    let cur = get_flags(path)?;
    let next = apply_immutable(cur, immutable);
    if next != cur {
        set_flags(path, next)?;
    }
    Ok(())
}

/// Best-effort query of the immutable bit for the posture self-check.
///
/// Returns `false` if the path cannot be opened or the ioctl fails (e.g. the file
/// is missing or lives on a filesystem without flag support) — callers treat
/// "cannot confirm immutable" the same as "not immutable".
#[must_use]
pub fn check_immutable(path: &Path) -> bool {
    get_flags(path).map(is_immutable).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_flag_constant_matches_linux_fs_h() {
        // /usr/include/linux/fs.h: #define FS_IMMUTABLE_FL 0x00000010
        assert_eq!(FS_IMMUTABLE_FL, 0x10);
    }

    #[test]
    fn apply_sets_and_clears_only_the_immutable_bit() {
        // Start from a word with several unrelated flags set.
        let other_bits: libc::c_long = 0x0000_0001 | 0x0000_0020 | 0x0000_0800;
        assert!(!is_immutable(other_bits));

        let set = apply_immutable(other_bits, true);
        assert!(is_immutable(set));
        // Unrelated bits are untouched.
        assert_eq!(set & !FS_IMMUTABLE_FL, other_bits);

        let cleared = apply_immutable(set, false);
        assert!(!is_immutable(cleared));
        // Round-trips back to the original word.
        assert_eq!(cleared, other_bits);
    }

    #[test]
    fn apply_is_idempotent() {
        let base: libc::c_long = 0x42;
        let once = apply_immutable(base, true);
        let twice = apply_immutable(once, true);
        assert_eq!(once, twice);

        let cleared_once = apply_immutable(once, false);
        let cleared_twice = apply_immutable(cleared_once, false);
        assert_eq!(cleared_once, cleared_twice);
    }

    #[test]
    fn is_immutable_reads_only_the_immutable_bit() {
        assert!(is_immutable(FS_IMMUTABLE_FL));
        assert!(is_immutable(FS_IMMUTABLE_FL | 0x1));
        assert!(!is_immutable(0));
        assert!(!is_immutable(0x20)); // a different flag, not immutable
    }

    #[test]
    fn set_immutable_without_root_fails_cleanly_on_a_tempfile() {
        // This exercises the syscall shell only when NOT privileged: a non-root
        // process must get a clean Err (typically EPERM) rather than succeed or
        // panic. When run as root (e.g. a privileged CI), skip — setting the bit
        // there would actually succeed and leave the tempfile immutable.
        if super::super::posture().is_root {
            return;
        }
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "aegis-tamper-immutable-test-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"x").expect("write tempfile");
        let res = set_immutable(&path, true);
        // get_flags may also fail with ENOTTY on filesystems without flag support
        // (e.g. tmpfs/overlayfs in some CI sandboxes); either way it must be Err,
        // never Ok, for an unprivileged caller.
        assert!(
            res.is_err(),
            "unprivileged set_immutable must fail, got {res:?}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
