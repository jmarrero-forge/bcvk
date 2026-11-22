//! Cross-platform kernel command-line parameters shared across backends.

/// Kernel arguments every ephemeral VM gets, whatever the backend.
pub const EPHEMERAL_KERNEL_ARGS: &[&str] = &[
    // This avoids having journald interact with the rootfs
    // at all, which lessens the I/O traffic for virtiofs (or NBD)
    "systemd.mask=systemd-journal-flush.service",
    // bootupd's automatic bootloader update needs a block device
    // backing /boot or /sysroot, but here the root is virtiofs (or a
    // read-only EROFS image on the vfkit backend), so the unit fails
    // and the system boots "degraded". Updating the
    // bootloader makes no sense in an ephemeral VM anyway, and images
    // will ship a bootupd without https://github.com/coreos/bootupd/pull/1072
    // (which skips this case) for a long time.
    "systemd.mask=bootloader-update.service",
    // See https://github.com/bootc-dev/bcvk/issues/22
    "selinux=0",
];
