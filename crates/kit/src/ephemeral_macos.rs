//! Ephemeral VM management commands for macOS (vfkit backend).

use std::process::{Command, Stdio};
use std::time::Duration;

use clap::Subcommand;
use color_eyre::eyre::bail;
use color_eyre::Result;

use crate::run_ephemeral_macos::{self, EphemeralVmMetadata};
use crate::vm_helpers::VmMetadataStore;

/// Options for `ephemeral run-ssh`, combining run options with optional SSH arguments.
#[derive(Debug, clap::Parser)]
pub struct RunEphemeralSshOpts {
    #[command(flatten)]
    pub run_opts: run_ephemeral_macos::RunEphemeralOpts,

    /// SSH command to execute (optional, defaults to interactive shell)
    #[arg(trailing_var_arg = true)]
    pub ssh_args: Vec<String>,
}

/// Subcommands for ephemeral VM management.
#[derive(Debug, Subcommand)]
pub enum EphemeralCommands {
    /// Run bootc containers as ephemeral VMs
    #[clap(name = "run")]
    Run(run_ephemeral_macos::RunEphemeralOpts),

    /// Run ephemeral VM and SSH into it
    #[clap(name = "run-ssh")]
    RunSsh(RunEphemeralSshOpts),

    /// Connect to a running ephemeral VM via SSH
    #[clap(name = "ssh")]
    Ssh {
        /// VM name
        name: String,

        /// Additional SSH arguments (e.g. -v, -L, commands to execute)
        #[clap(allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// List ephemeral VM containers
    #[clap(name = "ps")]
    Ps {
        /// Output as JSON
        #[clap(long)]
        json: bool,
    },

    /// Remove all ephemeral VM containers
    #[clap(name = "rm-all")]
    RmAll {
        /// Force removal without confirmation
        #[clap(short, long)]
        force: bool,
    },
}

impl EphemeralCommands {
    /// Execute the ephemeral subcommand.
    pub fn run(self) -> Result<()> {
        match self {
            EphemeralCommands::Run(opts) => run_ephemeral_macos::run(opts),
            EphemeralCommands::RunSsh(mut opts) => {
                opts.run_opts.ssh_keygen = true;
                if !opts.ssh_args.is_empty() {
                    let combined = shlex::try_join(opts.ssh_args.iter().map(|s| s.as_str()))
                        .map_err(|e| color_eyre::eyre::eyre!("failed to escape SSH args: {}", e))?;
                    opts.run_opts.execute.push(combined);
                }
                run_ephemeral_macos::run(opts.run_opts)
            }
            EphemeralCommands::Ssh { name, args } => cmd_ssh(&name, &args),
            EphemeralCommands::Ps { json } => cmd_ps(json),
            EphemeralCommands::RmAll { force } => cmd_rm_all(force),
        }
    }
}

/// Stop what is left of an ephemeral VM and forget it.
///
/// Its processes are killed outright, as its root is a read-only export,
/// its bcvk process first, so that it doesn't start anything more. The
/// VM must go before the NBD server backing its root filesystem. gvproxy
/// and the NBD server outlive a VM whose bcvk process didn't clean up
/// after it (it was killed, say), so they are stopped even when vfkit has
/// exited.
pub(crate) fn release(vm: &EphemeralVmMetadata) {
    crate::vm_helpers::terminate_process(vm.owner, "bcvk", Duration::ZERO, true);
    crate::vm_helpers::stop_vm_processes(vm.vfkit, vm.gvproxy, true);
    if let Some(ref name) = vm.nbd_unit {
        crate::nbd_macos::stop_nbd_server(name, vm.nbd_port);
    }
    EphemeralVmMetadata::remove(&vm.name);
}

/// Release a VM found gone, see [`release`], if it still is: under the
/// VM names lock, and only if its name wasn't taken by a new VM since,
/// whose resources this would release instead.
fn release_if_gone(vm: &EphemeralVmMetadata) {
    let release_it = || -> Result<()> {
        let _lock = EphemeralVmMetadata::lock()?;
        if let Some(cur) = EphemeralVmMetadata::load_if_exists(&vm.name)? {
            if cur.same_vm(vm) && !cur.is_alive() {
                release(&cur);
            }
        }
        Ok(())
    };
    if let Err(e) = release_it() {
        tracing::warn!("failed to release ephemeral VM '{}': {e}", vm.name);
    }
}

fn cmd_ps(json: bool) -> Result<()> {
    let (live, stale): (Vec<_>, Vec<_>) = EphemeralVmMetadata::list_readable()?
        .into_iter()
        .partition(|vm| vm.is_alive());
    stale.iter().for_each(release_if_gone);

    if json {
        println!("{}", serde_json::to_string_pretty(&live)?);
        return Ok(());
    }

    if live.is_empty() {
        println!("No running ephemeral VMs.");
        return Ok(());
    }

    println!("{:<24} {:<50} SSH", "NAME", "IMAGE");
    for vm in &live {
        if !vm.vfkit.is_running() {
            println!("{:<24} {:<50} (starting)", vm.name, vm.image);
            continue;
        }
        println!(
            "{:<24} {:<50} ssh -p {} -i {} root@{}",
            vm.name,
            vm.image,
            vm.ssh_port,
            vm.ssh_key,
            crate::vm_helpers::FORWARD_LOCALHOST
        );
    }
    Ok(())
}

fn cmd_rm_all(force: bool) -> Result<()> {
    let vms = EphemeralVmMetadata::list_readable()?;
    if vms.is_empty() {
        println!("No ephemeral VMs found.");
        return Ok(());
    }

    if !force {
        println!("Found {} ephemeral VM(s):", vms.len());
        for vm in &vms {
            println!(
                "  {} ({})",
                vm.name,
                if vm.is_alive() { "running" } else { "stopped" }
            );
        }
        if !crate::utils::confirm("Remove all ephemeral VMs?")? {
            println!("Aborted.");
            return Ok(());
        }
    }

    for vm in &vms {
        release(vm);
        println!("Removed {}", vm.name);
    }

    // Sweep orphaned resources inside podman machine
    if let Ok(machine) = crate::vm_helpers::detect_machine_name() {
        // Stop orphaned bcvk-nbd systemd units
        if let Err(e) = Command::new("podman")
            .args([
                "machine",
                "ssh",
                &machine,
                "--",
                "bash", "-c",
                "for u in $(systemctl list-units --plain --no-legend 'bcvk-nbd-*' 2>/dev/null | awk '{print $1}'); do systemctl stop $u 2>/dev/null; systemctl reset-failed $u 2>/dev/null; done",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            tracing::debug!("failed to stop orphaned nbd units: {}", e);
        }
        // Unmount any remaining container image overlays
        if let Err(e) = Command::new("podman")
            .args([
                "machine", "ssh", &machine, "--", "podman", "image", "umount", "--all",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            tracing::debug!("failed to unmount container images: {}", e);
        }
    }
    Ok(())
}

fn cmd_ssh(name: &str, args: &[String]) -> Result<()> {
    let vm = EphemeralVmMetadata::load(name)?;
    if !vm.is_alive() {
        release_if_gone(&vm);
        bail!("VM '{}' is not running", name);
    }
    if !vm.vfkit.is_running() {
        bail!("VM '{}' is still starting", name);
    }

    // Try to set up SSH port forwarding via VM-specific gvproxy socket
    let base = run_ephemeral_macos::ephemeral_base_dir();
    let svc_sock = crate::vm_helpers::gvproxy_socket_paths(&base, name)?
        .1
        .to_string_lossy()
        .to_string();
    if std::path::Path::new(&svc_sock).exists() {
        if let Err(e) = crate::vm_helpers::expose_port(
            &svc_sock,
            crate::vm_helpers::FORWARD_LOCALHOST,
            vm.ssh_port,
            crate::vm_helpers::GVPROXY_VM_IP,
            22,
        ) {
            tracing::debug!("SSH port forward re-expose: {}", e);
        }
    }

    let key_path = std::path::Path::new(&vm.ssh_key);
    if args.is_empty() {
        crate::vm_helpers::run_ssh_interactive(vm.ssh_port, key_path, "root")?;
    } else {
        let combined = shlex::try_join(args.iter().map(|s| s.as_str()))
            .map_err(|e| color_eyre::eyre::eyre!("failed to escape SSH command: {}", e))?;
        let status = crate::vm_helpers::run_ssh_command(vm.ssh_port, key_path, "root", &combined)?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    }
    Ok(())
}
