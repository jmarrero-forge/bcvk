//! vm stop — Stop a running persistent VM.

use super::{VmMetadata, VmMetadataStore};
use color_eyre::{eyre::bail, Result};
use tracing::info;

/// Options for `vm stop`.
#[derive(clap::Parser, Debug)]
pub struct VmStopOpts {
    /// VM name
    pub name: String,
    /// Force immediate power-off (SIGKILL) instead of graceful shutdown
    #[clap(long, short = 'f')]
    pub force: bool,
}

/// Stop a running persistent VM.
///
/// gvproxy keeps running, holding the VM's forwarded ports, after the
/// guest powered itself off, so it is stopped then too.
pub fn run(opts: VmStopOpts) -> Result<()> {
    let mut meta = VmMetadata::load(&opts.name)?;
    let running = meta.is_alive();
    if !running && !meta.gvproxy.is_running() {
        bail!("VM '{}' is not running", opts.name);
    }

    if running {
        info!("stopping VM '{}'...", opts.name);
    } else {
        info!(
            "VM '{}' already powered off, stopping its gvproxy",
            opts.name
        );
    }
    meta.stop_processes(opts.force);

    meta.state = "stopped".to_string();
    meta.vfkit = crate::vm_helpers::TrackedProcess::NONE;
    meta.gvproxy = crate::vm_helpers::TrackedProcess::NONE;
    meta.save()?;

    println!("Stopped '{}'", opts.name);
    Ok(())
}
