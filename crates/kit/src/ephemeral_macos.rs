//! Ephemeral VM management commands for macOS (vfkit backend).

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

/// How long the bcvk process running an ephemeral VM gets to tear it
/// down after SIGTERM. It may first have to finish starting the NBD
/// server, which can take half a minute.
const OWNER_STOP_TIMEOUT: Duration = Duration::from_secs(60);

/// Stop an ephemeral VM's processes and its NBD server.
///
/// The processes are killed outright, as the VM's root is a read-only
/// export, and the VM must go before the NBD server backing it. gvproxy
/// and the NBD server outlive a VM whose bcvk process didn't clean up
/// after it (it was killed, say), so they are stopped even when vfkit has
/// exited.
pub(crate) fn stop_vm(vm: &EphemeralVmMetadata) {
    crate::vm_helpers::stop_vm_processes(vm.vfkit, vm.gvproxy, true);
    if let Some(ref name) = vm.nbd_unit {
        crate::nbd_macos::stop_nbd_server(name, vm.nbd_port);
    }
}

/// Stop what is left of an ephemeral VM, see [`stop_vm`], and forget it.
///
/// For a VM whose bcvk process is gone: one still running would go on
/// starting things, so it is killed first, but it is better asked to
/// clean up itself, see [`remove`].
pub(crate) fn release(vm: &EphemeralVmMetadata) {
    crate::vm_helpers::terminate_process(vm.owner, "bcvk", Duration::ZERO, true);
    stop_vm(vm);
    EphemeralVmMetadata::remove(&vm.name);
}

/// Remove an ephemeral VM, running or not.
///
/// Its bcvk process, if it still runs, tears it down itself on SIGTERM,
/// even while it is still starting it; whatever is left after that, or by
/// a bcvk process that was killed, is released here, under the VM names
/// lock. A detached VM's bcvk process may have taken the VM over from
/// the one starting it meanwhile, which then gets the same treatment.
fn remove(vm: &EphemeralVmMetadata) -> Result<()> {
    let mut owner = vm.owner;
    // The bcvk process --detach started, then the one it started
    for _ in 0..2 {
        crate::vm_helpers::terminate_process(owner, "bcvk", OWNER_STOP_TIMEOUT, false);
        let _lock = EphemeralVmMetadata::lock()?;
        match EphemeralVmMetadata::load_if_exists(&vm.name)? {
            Some(cur) if cur.same_vm(vm) && cur.owner != owner && cur.owner.is_running() => {
                owner = cur.owner;
            }
            Some(cur) if cur.same_vm(vm) => {
                release(&cur);
                return Ok(());
            }
            // Gone, or a new VM under that name
            _ => return Ok(()),
        }
    }
    Err(color_eyre::eyre::eyre!(
        "the bcvk process running VM '{}' kept changing",
        vm.name
    ))
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
        match remove(vm) {
            Ok(()) => println!("Removed {}", vm.name),
            Err(e) => tracing::warn!("failed to remove ephemeral VM '{}': {e}", vm.name),
        }
    }

    if let Err(e) = sweep_orphans() {
        tracing::warn!("failed to clean up after removed ephemeral VMs: {e}");
    }
    Ok(())
}

/// Stop the NBD servers, and unmount the images, that no ephemeral VM
/// uses any more, such as those of one whose bcvk process was killed.
///
/// Those of a VM that is alive, which another bcvk process may have
/// started after rm-all listed the VMs, are spared, as are those of a VM
/// whose metadata can't be read, as it might be. Under the VM names lock,
/// so that no VM can start under a name meanwhile; each podman machine
/// command is bounded by [`crate::vm_helpers::MACHINE_SSH_TIMEOUT`], so
/// that the lock isn't held for good.
fn sweep_orphans() -> Result<()> {
    let machine = crate::vm_helpers::detect_machine_name()?;
    let _lock = EphemeralVmMetadata::lock()?;
    let in_use: Vec<String> = crate::vm_helpers::read_all_metadata::<EphemeralVmMetadata>(
        &EphemeralVmMetadata::vms_dir(),
    )?
    .into_iter()
    .filter(|(_, meta)| meta.as_ref().map_or(true, EphemeralVmMetadata::is_alive))
    .filter_map(|(path, _)| Some(path.file_stem()?.to_string_lossy().into_owned()))
    .collect();

    // Each command bounded, as a hung podman machine would otherwise keep
    // every ephemeral VM from starting, waiting for the lock
    let timeout = crate::vm_helpers::MACHINE_SSH_TIMEOUT;
    let units = crate::vm_helpers::machine_ssh_output_within(&machine, NBD_UNITS_CMD, timeout)?;
    if !units.status.success() {
        bail!(
            "listing the NBD servers failed: {}",
            String::from_utf8_lossy(&units.stderr).trim()
        );
    }
    for unit in orphaned_nbd_units(&String::from_utf8_lossy(&units.stdout), &in_use) {
        crate::vm_helpers::stop_nbd_unit_within(&machine, unit, timeout)?;
    }
    // Image mounts aren't per VM
    if in_use.is_empty() {
        let umount = crate::vm_helpers::machine_ssh_output_within(
            &machine,
            "podman image umount --all",
            timeout,
        )?;
        if !umount.status.success() {
            tracing::debug!(
                "failed to unmount container images: {}",
                String::from_utf8_lossy(&umount.stderr).trim()
            );
        }
    }
    Ok(())
}

/// Lists the NBD server units in the podman machine, one per line, the
/// unit's name first.
const NBD_UNITS_CMD: &str = "systemctl list-units --plain --no-legend 'bcvk-nbd-*'";

/// The units in `units`, the output of [`NBD_UNITS_CMD`], that aren't the
/// NBD server of a VM in `in_use`.
fn orphaned_nbd_units<'a>(units: &'a str, in_use: &[String]) -> Vec<&'a str> {
    units
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|unit| {
            let unit = unit.strip_suffix(".service").unwrap_or(unit);
            !in_use
                .iter()
                .any(|name| crate::nbd_macos::nbd_unit_name(name) == unit)
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_helpers::TrackedProcess;

    /// A process to stand in for a VM's bcvk process, which exits on SIGTERM.
    fn spawn_owner() -> (std::process::Child, TrackedProcess) {
        let child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let tracked = TrackedProcess::new(child.id());
        (child, tracked)
    }

    #[test]
    fn test_remove() {
        let _dir = crate::vm_helpers::use_test_base_dir();
        let vm = |owner| EphemeralVmMetadata {
            owner,
            ..EphemeralVmMetadata::reserved("vm", "img", false)
        };

        // Its bcvk process is stopped, and then what is left released
        let (_child, owner) = spawn_owner();
        let running = vm(owner);
        running.save().unwrap();
        remove(&running).unwrap();
        assert!(!owner.is_running());
        assert!(EphemeralVmMetadata::load_if_exists("vm").unwrap().is_none());

        // ... and the one that took the VM over meanwhile, as a detached
        // VM's does from the one that started it
        let (_parent, parent) = spawn_owner();
        let (_child, child) = spawn_owner();
        let starting = vm(parent);
        EphemeralVmMetadata {
            owner: child,
            ..starting.clone()
        }
        .save()
        .unwrap();
        remove(&starting).unwrap();
        assert!(!parent.is_running() && !child.is_running());
        assert!(EphemeralVmMetadata::load_if_exists("vm").unwrap().is_none());

        // A new VM that took the name meanwhile is left alone
        let new_vm = EphemeralVmMetadata {
            created: "2999-01-01T00:00:00Z".into(),
            ..vm(TrackedProcess::current())
        };
        new_vm.save().unwrap();
        remove(&vm(TrackedProcess::NONE)).unwrap();
        assert!(EphemeralVmMetadata::load("vm").unwrap().same_vm(&new_vm));
    }

    #[test]
    fn test_orphaned_nbd_units() {
        let units = "bcvk-nbd-a.service loaded active running /usr/bin/bcvk-nbd\n\
                     bcvk-nbd-a-2.service loaded failed failed /usr/bin/bcvk-nbd\n\
                     bcvk-nbd-b.service loaded active running /usr/bin/bcvk-nbd\n\
                     \n";
        for (in_use, orphaned) in [
            (
                &[][..],
                &[
                    "bcvk-nbd-a.service",
                    "bcvk-nbd-a-2.service",
                    "bcvk-nbd-b.service",
                ][..],
            ),
            (
                &["a".to_string()][..],
                &["bcvk-nbd-a-2.service", "bcvk-nbd-b.service"][..],
            ),
            (
                &["a-2".to_string(), "b".to_string()][..],
                &["bcvk-nbd-a.service"][..],
            ),
        ] {
            assert_eq!(orphaned_nbd_units(units, in_use), orphaned, "{in_use:?}");
        }
    }
}
