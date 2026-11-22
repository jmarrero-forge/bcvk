//! vm rm — Remove a persistent VM and its metadata.

use std::fs;

use clap::Parser;
use color_eyre::Result;
use tracing::info;

use super::{VmMetadata, VmMetadataStore};

/// Options for `vm rm`.
#[derive(Parser, Debug)]
pub struct VmRmOpts {
    /// VM name
    pub name: String,
    /// Force removal even if running
    #[clap(short, long)]
    pub force: bool,
    /// Stop domain if it's running (implied by --force)
    #[clap(long)]
    pub stop: bool,
}

/// Remove a persistent VM, optionally force-killing it.
pub fn run(opts: VmRmOpts) -> Result<()> {
    let meta = VmMetadata::load(&opts.name)?;

    if meta.is_alive() {
        if !(opts.force || opts.stop) {
            color_eyre::eyre::bail!(
                "VM '{}' is running. Stop it first or use --force/--stop",
                opts.name
            );
        }
        info!("stopping VM '{}'...", opts.name);
        // --stop shuts the guest down cleanly, --force kills it
        crate::vfkit::stop::run(crate::vfkit::stop::VmStopOpts {
            name: opts.name.clone(),
            force: opts.force,
        })?;
    } else {
        // gvproxy outlives a guest that powered itself off
        meta.stop_processes(true);
    }

    remove_own_disk(&meta);
    let vms_dir = VmMetadata::vms_dir();

    for path in [&meta.efi_store, &meta.serial_log] {
        if !path.is_empty() {
            if let Err(e) = fs::remove_file(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::debug!("failed to remove {}: {}", path, e);
                }
            }
        }
    }

    for suffix in ["-gvproxy.sock", "-gvproxy-svc.sock"] {
        let p = vms_dir.join(format!("{}{}", meta.name, suffix));
        if let Err(e) = fs::remove_file(&p) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::debug!("failed to remove {}: {}", p.display(), e);
            }
        }
    }

    VmMetadata::remove(&opts.name);
    println!("Removed '{}'", opts.name);
    Ok(())
}

/// Remove the disk image and SSH keys of a VM if bcvk made them (see
/// [`VmMetadata::has_own_disk`]); a disk of the user's own is left alone.
pub(crate) fn remove_own_disk(meta: &VmMetadata) {
    if !meta.has_own_disk() {
        return;
    }
    for path in [
        meta.disk_image.clone(),
        format!("{}.key", meta.disk_image),
        format!("{}.key.pub", meta.disk_image),
    ] {
        if let Err(e) = fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::debug!("failed to remove {}: {}", path, e);
            }
        }
    }
}
