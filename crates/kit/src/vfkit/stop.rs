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
pub fn run(opts: VmStopOpts) -> Result<()> {
    let mut meta = VmMetadata::load(&opts.name)?;
    if !meta.is_alive() {
        bail!("VM '{}' is not running", opts.name);
    }

    info!("stopping VM '{}'...", opts.name);
    meta.stop_processes(opts.force);

    meta.state = "stopped".to_string();
    meta.vfkit = crate::vm_helpers::TrackedProcess::NONE;
    meta.gvproxy = crate::vm_helpers::TrackedProcess::NONE;
    meta.save()?;

    println!("Stopped '{}'", opts.name);
    Ok(())
}
