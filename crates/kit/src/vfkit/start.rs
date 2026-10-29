//! vm start — Restart a stopped persistent VM.

use clap::Parser;
use color_eyre::{eyre::bail, Result};

use super::{VmMetadata, VmMetadataStore};
use crate::vm_helpers::{clear_xattr, run_ssh_interactive};

/// Options for `vm start`.
#[derive(Parser, Debug)]
pub struct VmStartOpts {
    /// VM name
    pub name: String,
    /// Display VM console in GUI window
    #[clap(long)]
    pub gui: bool,
    /// Automatically SSH into the VM after starting
    #[clap(long)]
    pub ssh: bool,
}

/// Restart a stopped persistent VM by re-launching vfkit.
pub fn run(opts: VmStartOpts) -> Result<()> {
    let mut meta = VmMetadata::load(&opts.name)?;
    if meta.is_alive() {
        bail!("VM '{}' is already running", opts.name);
    }

    if !std::path::Path::new(&meta.disk_image).exists() {
        bail!("disk image not found: {}", meta.disk_image);
    }
    clear_xattr(std::path::Path::new(&meta.disk_image));

    meta.gui = opts.gui || meta.gui;
    let (vfkit_child, gvproxy_child) = super::launch(&meta)?;
    meta.vfkit_pid = vfkit_child.id();
    meta.gvproxy_pid = gvproxy_child.id();
    meta.state = "running".to_string();
    meta.save()?;

    println!("Started '{}'", meta.name);
    println!(
        "  ssh -p {} -i {} root@{}",
        meta.ssh_port,
        meta.ssh_key,
        crate::vm_helpers::FORWARD_LOCALHOST
    );

    if opts.ssh {
        let key_path = std::path::Path::new(&meta.ssh_key);
        let status = run_ssh_interactive(meta.ssh_port, key_path, "root")?;
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}
