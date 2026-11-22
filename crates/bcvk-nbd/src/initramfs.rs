//! CPIO newc archive generation for initramfs append.
//!
//! The archives built here are appended to the image's own initramfs, which
//! the kernel unpacks over it, to add bcvk's systemd units to the initrd.

use std::io::Write;

use cpio::newc::Builder as NewcBuilder;
use cpio::newc::ModeFileType;

/// Writes into a `Vec` can't fail, so neither can building these archives.
const VEC_WRITE: &str = "writing a CPIO archive to a Vec";

/// Directory for unit files in the initramfs.
const UNIT_DIR: &str = "usr/lib/systemd/system";

/// The tmpfiles.d snippet carrying root's SSH key, as shipped in the initramfs.
const ROOT_SSH_TMPFILES: &str = "usr/lib/bcvk/root-ssh.conf";

/// Unit copying [`ROOT_SSH_TMPFILES`] to `/run/tmpfiles.d/`, which survives
/// the switch to the real root, where systemd-tmpfiles-setup.service applies it.
///
/// tmpfiles.d snippets apply in the order of their file names, and `/root`
/// usually links to `/var/roothome`, which the image's own snippets create
/// (Fedora's `rpm-ostree-0-integration.conf`, for instance). So the name
/// starts with `zz-` to come after them, as the `tmpfiles.extra` credential
/// of the QEMU backend is read after all files.
const ROOT_SSH_TMPFILES_UNIT: &[u8] = b"[Unit]
Description=Install root's SSH key for the booted system
DefaultDependencies=no
ConditionPathExists=/etc/initrd-release
Before=initrd-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/mkdir -p /run/tmpfiles.d
ExecStart=/usr/bin/cp /usr/lib/bcvk/root-ssh.conf /run/tmpfiles.d/zz-bcvk-root-ssh.conf
";

/// Append a directory entry.
fn write_dir(out: &mut Vec<u8>, path: &str) {
    NewcBuilder::new(path)
        .mode(0o755)
        .set_mode_file_type(ModeFileType::Directory)
        .write(out, 0)
        .finish()
        .expect(VEC_WRITE);
}

/// Append a regular file with mode 0644.
fn write_file(out: &mut Vec<u8>, path: &str, data: &[u8]) {
    let mut w = NewcBuilder::new(path)
        .mode(0o644)
        .set_mode_file_type(ModeFileType::Regular)
        .write(out, data.len() as u32);
    w.write_all(data).expect(VEC_WRITE);
    w.finish().expect(VEC_WRITE);
}

/// Append the unit directory and its `initrd-fs.target.d` drop-in directory.
fn write_unit_dirs(out: &mut Vec<u8>) {
    for dir in [
        "usr",
        "usr/lib",
        "usr/lib/systemd",
        UNIT_DIR,
        "usr/lib/systemd/system/initrd-fs.target.d",
    ] {
        write_dir(out, dir);
    }
}

/// Append the service `{name}.service` and the drop-in making
/// `initrd-fs.target` want it.
fn write_initrd_service(out: &mut Vec<u8>, name: &str, unit: &[u8]) {
    write_file(out, &format!("{UNIT_DIR}/{name}.service"), unit);
    write_file(
        out,
        &format!("{UNIT_DIR}/initrd-fs.target.d/{name}.conf"),
        format!("[Unit]\nWants={name}.service\n").as_bytes(),
    );
}

/// Build the archive with the initrd units every ephemeral VM uses: an
/// ephemeral `/var` and `/etc`, and a writable `/root/.ssh` when `/root`
/// isn't a symlink into `/var`. These are the same units the QEMU backend
/// adds to its initramfs.
pub fn build_units_cpio() -> Vec<u8> {
    let mut out = Vec::with_capacity(32768);
    write_unit_dirs(&mut out);

    for (name, unit) in [
        (
            "bcvk-var-ephemeral",
            &include_bytes!("../../kit/src/units/bcvk-var-ephemeral.service")[..],
        ),
        (
            "bcvk-etc-overlay",
            &include_bytes!("../../kit/src/units/bcvk-etc-overlay.service")[..],
        ),
        (
            "bcvk-copy-units",
            &include_bytes!("../../kit/src/units/bcvk-copy-units.service")[..],
        ),
        (
            "bcvk-root-ssh-overlay",
            &include_bytes!("../../kit/src/units/bcvk-root-ssh-overlay.service")[..],
        ),
    ] {
        write_initrd_service(&mut out, name, unit);
    }

    write_file(
        &mut out,
        &format!("{UNIT_DIR}/bcvk-journal-stream.service"),
        b"[Unit]\n\
          Description=Stream journal to virtio-serial\n\
          DefaultDependencies=no\n\
          \n\
          [Service]\n\
          Type=simple\n\
          ExecStart=/bin/sh -c 'journalctl -f --no-hostname -o short-monotonic > /dev/hvc1 2>&1 || true'\n",
    );

    cpio::newc::trailer(out).expect(VEC_WRITE)
}

/// The tmpfiles.d lines installing `pubkey` as root's authorized key.
///
/// This is what the QEMU backend passes as the `tmpfiles.extra` credential
/// (`bcvk_qemu::key_to_root_tmpfiles_d`); the key is base64 encoded, so it
/// can't break out of its field.
fn root_ssh_tmpfiles(pubkey: &str) -> String {
    let key = data_encoding::BASE64.encode(pubkey.as_bytes());
    format!("d /root/.ssh 0750 - - -\nf+~ /root/.ssh/authorized_keys 700 - - - {key}\n")
}

/// Build the archive giving root on the booted system `pubkey` as its SSH key.
///
/// The QEMU backend passes the key as a systemd credential, but vfkit can
/// provide neither SMBIOS nor fw_cfg, so the key comes as a tmpfiles.d
/// snippet in the initramfs instead, which a unit hands over to the real
/// root through `/run`. The booted system then installs it the same way
/// as the credential.
pub fn build_ssh_cpio(pubkey: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4096);
    write_unit_dirs(&mut out);
    write_dir(&mut out, "usr/lib/bcvk");
    write_file(
        &mut out,
        ROOT_SSH_TMPFILES,
        root_ssh_tmpfiles(pubkey).as_bytes(),
    );
    write_initrd_service(&mut out, "bcvk-root-ssh-tmpfiles", ROOT_SSH_TMPFILES_UNIT);
    cpio::newc::trailer(out).expect(VEC_WRITE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read back the (name, contents) of the regular files in an archive.
    fn read_files(mut archive: &[u8]) -> Vec<(String, String)> {
        let mut files = Vec::new();
        loop {
            let mut reader = cpio::NewcReader::new(archive).unwrap();
            let entry = reader.entry();
            if entry.is_trailer() {
                break;
            }
            let name = entry.name().to_string();
            let is_file = entry.mode() & 0o170000 == 0o100000;
            let mut contents = String::new();
            std::io::Read::read_to_string(&mut reader, &mut contents).unwrap();
            if is_file {
                files.push((name, contents));
            }
            archive = reader.finish().unwrap();
        }
        files
    }

    #[test]
    fn test_root_ssh_tmpfiles() {
        // Same expectation as bcvk_qemu's test_key_to_root_tmpfiles_d
        let key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...";
        let expected = "d /root/.ssh 0750 - - -\nf+~ /root/.ssh/authorized_keys 700 - - - c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCQVFDLi4u\n";
        assert_eq!(root_ssh_tmpfiles(key), expected);
    }

    #[test]
    fn test_build_ssh_cpio() {
        // Quotes can't escape anything: the key is base64 encoded
        let key = "ssh-ed25519 AAAA' ; touch /pwned ; ' bcvk";
        let files = read_files(&build_ssh_cpio(key));
        let expected = [
            (ROOT_SSH_TMPFILES, root_ssh_tmpfiles(key)),
            (
                "usr/lib/systemd/system/bcvk-root-ssh-tmpfiles.service",
                String::from_utf8(ROOT_SSH_TMPFILES_UNIT.to_vec()).unwrap(),
            ),
            (
                "usr/lib/systemd/system/initrd-fs.target.d/bcvk-root-ssh-tmpfiles.conf",
                "[Unit]\nWants=bcvk-root-ssh-tmpfiles.service\n".to_string(),
            ),
        ];
        let files: Vec<_> = files.iter().map(|(n, c)| (n.as_str(), c.clone())).collect();
        assert_eq!(files, expected);
        let unit = std::str::from_utf8(ROOT_SSH_TMPFILES_UNIT).unwrap();
        assert!(unit.contains(&format!(" /{ROOT_SSH_TMPFILES} ")), "{unit}");
    }

    #[test]
    fn test_build_units_cpio() {
        let names: Vec<_> = read_files(&build_units_cpio())
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        for unit in [
            "bcvk-var-ephemeral",
            "bcvk-etc-overlay",
            "bcvk-copy-units",
            "bcvk-root-ssh-overlay",
        ] {
            assert!(
                names.contains(&format!("{UNIT_DIR}/{unit}.service")),
                "{unit}"
            );
            assert!(
                names.contains(&format!("{UNIT_DIR}/initrd-fs.target.d/{unit}.conf")),
                "{unit}"
            );
        }
    }
}
