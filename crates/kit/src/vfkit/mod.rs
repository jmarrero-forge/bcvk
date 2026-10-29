//! Persistent VM management for macOS using vfkit + EFI boot.
//!
//! Subcommands mirror the Linux libvirt/ module structure:
//! run, list, ssh, stop, start, rm, rm-all, inspect

use std::path::{Path, PathBuf};

use clap::Subcommand;
use color_eyre::{
    eyre::{bail, eyre},
    Result,
};
use tracing::info;

use crate::vm_helpers::TrackedProcess;
pub use crate::vm_helpers::VmMetadataStore;

pub mod inspect;
pub mod list;
pub mod rm;
pub mod rm_all;
pub mod run;
pub mod ssh;
pub mod start;
pub mod stop;

/// Output format for inspect and list commands.
#[derive(Debug, Clone, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum OutputFormat {
    /// Table format (default for list)
    Table,
    /// JSON format
    Json,
    /// YAML-like key-value format (default for inspect)
    Yaml,
    /// XML format (not yet implemented)
    Xml,
}

/// Subcommands for persistent VM management via vfkit.
#[derive(Debug, Subcommand)]
pub enum VmCommands {
    /// Run a persistent VM from a disk image
    Run(run::VmRunOpts),

    /// List all persistent VMs
    #[clap(name = "list", alias = "ls")]
    List(list::VmListOpts),

    /// SSH into a running VM
    Ssh(ssh::VmSshOpts),

    /// Stop a running VM
    Stop(stop::VmStopOpts),

    /// Start a stopped VM
    Start(start::VmStartOpts),

    /// Remove a VM and its metadata
    #[clap(name = "rm")]
    Remove(rm::VmRmOpts),

    /// Remove all VMs
    #[clap(name = "rm-all")]
    RemoveAll(rm_all::VmRmAllOpts),

    /// Show detailed VM information
    Inspect(inspect::VmInspectOpts),
}

impl VmCommands {
    /// Dispatch to the appropriate subcommand handler.
    pub fn run(self) -> Result<()> {
        match self {
            VmCommands::Run(opts) => run::run(opts),
            VmCommands::List(opts) => list::run(opts),
            VmCommands::Ssh(opts) => ssh::run(opts),
            VmCommands::Stop(opts) => stop::run(opts),
            VmCommands::Start(opts) => start::run(opts),
            VmCommands::Remove(opts) => rm::run(opts),
            VmCommands::RemoveAll(opts) => rm_all::run(opts),
            VmCommands::Inspect(opts) => inspect::run(opts),
        }
    }
}

// --- VM Metadata ---

/// Persistent VM metadata, stored as JSON in `~/.local/share/bcvk/vms/`.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct VmMetadata {
    /// VM name used as identifier.
    pub name: String,
    /// Container image used to create this VM (None if created from disk directly).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Path to the disk image file.
    pub disk_image: String,
    /// The vfkit process.
    #[serde(default)]
    pub vfkit: TrackedProcess,
    /// The gvproxy network proxy process.
    #[serde(default)]
    pub gvproxy: TrackedProcess,
    /// Host-side SSH port forwarded to the VM.
    pub ssh_port: u16,
    /// Path to the SSH private key.
    pub ssh_key: String,
    /// Number of vCPUs allocated.
    pub vcpus: u32,
    /// Memory in megabytes.
    pub memory_mb: u32,
    /// Path to the EFI variable store file.
    pub efi_store: String,
    /// Path to the serial console log file.
    pub serial_log: String,
    /// Whether GUI mode is enabled.
    pub gui: bool,
    /// ISO 8601 timestamp when the VM was created.
    pub created: String,
    /// Current VM state (running, stopped).
    pub state: String,
    /// User-defined labels for organizing VMs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// Port mappings from host to VM (host_port, guest_port).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_mappings: Vec<(u16, u16)>,
}

impl crate::vm_helpers::VmMetadataStore for VmMetadata {
    fn vms_dir() -> PathBuf {
        crate::vm_helpers::bcvk_base_dir().join("vms")
    }
    fn name(&self) -> &str {
        &self.name
    }
}

impl VmMetadata {
    /// Check if the VM process is still alive.
    pub fn is_alive(&self) -> bool {
        self.vfkit.is_running()
    }

    /// Stop the VM's vfkit and gvproxy processes, see
    /// [`crate::vm_helpers::stop_vm_processes`].
    pub fn stop_processes(&self, force: bool) {
        crate::vm_helpers::stop_vm_processes(self.vfkit, self.gvproxy, force);
    }

    /// Whether bcvk made the VM's disk, from a container image, so that
    /// it goes with the VM; otherwise it is the user's own.
    pub fn has_own_disk(&self) -> bool {
        Path::new(&self.disk_image).starts_with(Self::vms_dir())
    }
}

/// Whether [`launch`] starts a VM just created, which has no saved
/// metadata yet, or one whose metadata is saved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Launch {
    /// `vm run`
    New,
    /// `vm start`
    Saved,
}

/// Fail if a running VM other than the named one uses `disk`: two VMs
/// writing to one disk would corrupt it.
///
/// Fails on metadata it can't read too, see [`VmMetadataStore::list_all`].
pub(crate) fn check_disk_not_in_use(name: &str, disk: &str) -> Result<()> {
    if let Some(other) = VmMetadata::list_all()?
        .into_iter()
        .find(|vm| vm.name != name && vm.disk_image == disk && vm.is_alive())
    {
        bail!(
            "disk image {disk} is in use by the running VM '{}'",
            other.name
        );
    }
    Ok(())
}

/// Fail if the VM, or another one using its disk, runs already, see
/// [`check_disk_not_in_use`]; or if its saved metadata isn't the one
/// [`launch`] started from, as another bcvk command created or removed
/// the VM meanwhile.
fn check_launch(meta: &VmMetadata, launch: Launch) -> Result<()> {
    check_disk_not_in_use(&meta.name, &meta.disk_image)?;
    let name = &meta.name;
    match (VmMetadata::load_if_exists(name)?, launch) {
        (Some(saved), _) if saved.is_alive() => Err(eyre!("VM '{name}' is already running")),
        (Some(saved), Launch::Saved) if saved.created == meta.created => Ok(()),
        (None, Launch::New) => Ok(()),
        (Some(_), _) => Err(eyre!(
            "VM '{name}' was created by another bcvk command meanwhile"
        )),
        (None, Launch::Saved) => Err(eyre!("VM '{name}' was removed meanwhile")),
    }
}

/// Start gvproxy and vfkit for a persistent VM, save its metadata with
/// them, then forward its ports and wait for SSH. Fails if the VM, or
/// another one using the same disk, runs already, see [`check_launch`].
///
/// `prepare` runs first, for `vm run` to replace an existing VM and
/// create the disk. It, the check, starting the processes and saving them
/// happen under the VMs directory lock, so that two bcvk commands
/// launching VMs off one disk, or the same VM, at the same time can't
/// both pass the check, and neither can replace a disk the other's VM
/// runs from: each sees the processes the other started. On failure,
/// nothing is left running, and the saved metadata says so.
pub(crate) fn launch(
    meta: &mut VmMetadata,
    launch: Launch,
    prepare: impl FnOnce(&mut VmMetadata) -> Result<()>,
) -> Result<()> {
    use crate::vm_helpers::{
        expose_port, gvproxy_socket_paths, setup_ssh_port_forwarding, start_gvproxy, wait_for_ssh,
        FORWARD_ALL_INTERFACES, GVPROXY_VM_IP,
    };

    let (gvproxy_sock, services_sock) = gvproxy_socket_paths(&VmMetadata::vms_dir(), &meta.name)?;
    let services_sock = services_sock.to_string_lossy().to_string();

    {
        let _lock = VmMetadata::lock()?;
        prepare(meta)?;
        check_launch(meta, launch)?;

        info!("starting gvproxy...");
        let gvproxy = start_gvproxy(&gvproxy_sock.to_string_lossy(), &services_sock)?;
        meta.gvproxy = TrackedProcess::new(gvproxy.id());

        let config = crate::vm_helpers::VfkitConfig {
            vcpus: meta.vcpus,
            memory_mb: meta.memory_mb,
            efi_store: Path::new(&meta.efi_store),
            boot_disk: format!("virtio-blk,path={}", meta.disk_image),
            gvproxy_sock: &gvproxy_sock,
            serial_log: Path::new(&meta.serial_log),
            extra_devices: Vec::new(),
            gui: meta.gui,
        };
        info!("launching vfkit (EFI boot)...");
        meta.vfkit = TrackedProcess::NONE;
        match config.spawn(None) {
            Ok(vfkit) => meta.vfkit = TrackedProcess::new(vfkit.id()),
            Err(e) => {
                meta.stop_processes(true);
                return Err(e);
            }
        }
        meta.state = "running".to_string();
        meta.save()?;
    }

    let connect = || -> Result<()> {
        info!("setting up SSH port forwarding...");
        setup_ssh_port_forwarding(&services_sock, meta.ssh_port)?;
        for &(host_port, guest_port) in &meta.port_mappings {
            expose_port(
                &services_sock,
                FORWARD_ALL_INTERFACES,
                host_port,
                GVPROXY_VM_IP,
                guest_port,
            )?;
            info!("port {}:{} forwarded", host_port, guest_port);
        }
        wait_for_ssh(meta.ssh_port, Path::new(&meta.ssh_key), "root")
    };
    connect().inspect_err(|_| {
        meta.stop_processes(true);
        if let Err(e) = forget_launch(meta, launch) {
            tracing::warn!("failed to update the metadata of VM '{}': {e}", meta.name);
        }
    })
}

/// Undo saving the metadata of a VM whose launch failed after starting
/// it: a new VM's is removed, a saved VM's goes back to stopped. Unless
/// another bcvk command replaced or removed it since.
fn forget_launch(meta: &VmMetadata, launch: Launch) -> Result<()> {
    let _lock = VmMetadata::lock()?;
    if VmMetadata::load_if_exists(&meta.name)?
        .is_none_or(|cur| cur.created != meta.created || cur.vfkit != meta.vfkit)
    {
        return Ok(());
    }
    match launch {
        Launch::New => {
            VmMetadata::remove(&meta.name);
            Ok(())
        }
        Launch::Saved => VmMetadata {
            vfkit: TrackedProcess::NONE,
            gvproxy: TrackedProcess::NONE,
            state: "stopped".to_string(),
            ..meta.clone()
        }
        .save(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    pub(super) fn sample_vm_metadata(name: &str) -> VmMetadata {
        VmMetadata {
            name: name.to_string(),
            image: None,
            disk_image: "/tmp/disk.raw".to_string(),
            vfkit: TrackedProcess::NONE,
            gvproxy: TrackedProcess::NONE,
            ssh_port: 2222,
            ssh_key: "/tmp/key".to_string(),
            vcpus: 2,
            memory_mb: 4096,
            efi_store: "/tmp/efi.fd".to_string(),
            serial_log: "/tmp/serial.log".to_string(),
            gui: false,
            created: "2026-01-01T00:00:00Z".to_string(),
            state: "running".to_string(),
            labels: vec![],
            port_mappings: vec![],
        }
    }

    #[test]
    fn test_check_launch() {
        let _dir = crate::vm_helpers::use_test_base_dir();
        let vm = |name: &str, disk: &str, running: bool| VmMetadata {
            disk_image: disk.to_string(),
            vfkit: if running {
                TrackedProcess::current()
            } else {
                TrackedProcess::NONE
            },
            ..sample_vm_metadata(name)
        };
        let check = |meta: &VmMetadata, launch| {
            check_launch(meta, launch)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        };

        let a = vm("a", "/d/a.raw", false);
        assert_eq!(check(&a, Launch::New), "");
        assert!(check(&a, Launch::Saved).contains("removed meanwhile"));
        a.save().unwrap();
        assert_eq!(check(&a, Launch::Saved), "");
        assert!(check(&a, Launch::New).contains("created by another"));
        let recreated = VmMetadata {
            created: "2999-01-01T00:00:00Z".into(),
            ..a.clone()
        };
        assert!(check(&recreated, Launch::Saved).contains("created by another"));
        vm("a", "/d/a.raw", true).save().unwrap();
        assert!(check(&a, Launch::Saved).contains("already running"));

        // Another VM off the same disk, running or not
        vm("b", "/d/b.raw", false).save().unwrap();
        assert_eq!(check(&vm("c", "/d/b.raw", false), Launch::New), "");
        vm("b", "/d/b.raw", true).save().unwrap();
        assert!(check(&vm("c", "/d/b.raw", false), Launch::New).contains("running VM 'b'"));

        // Metadata that can't be read might be of a VM using the disk
        fs::write(
            VmMetadata::metadata_path("old").unwrap(),
            r#"{"name": "old", "pid": 12}"#,
        )
        .unwrap();
        assert!(check(&vm("d", "/d/d.raw", false), Launch::New).contains("old.json"));
    }

    #[test]
    fn test_forget_launch() {
        let _dir = crate::vm_helpers::use_test_base_dir();
        let launched = VmMetadata {
            vfkit: TrackedProcess {
                pid: 1,
                started_us: 2,
            },
            gvproxy: TrackedProcess {
                pid: 3,
                started_us: 4,
            },
            ..sample_vm_metadata("vm")
        };
        let recreated = VmMetadata {
            created: "2999-01-01T00:00:00Z".into(),
            ..launched.clone()
        };
        let restarted = VmMetadata {
            vfkit: TrackedProcess {
                pid: 5,
                started_us: 6,
            },
            ..launched.clone()
        };

        for launch in [Launch::New, Launch::Saved] {
            // Nothing saved: nothing to undo
            forget_launch(&launched, launch).unwrap();
            assert!(VmMetadata::load_if_exists("vm").unwrap().is_none());

            // Another command's VM, or a later start of this one, stays
            for other in [&recreated, &restarted] {
                other.save().unwrap();
                forget_launch(&launched, launch).unwrap();
                let saved = VmMetadata::load("vm").unwrap();
                assert_eq!((&saved.created, saved.vfkit), (&other.created, other.vfkit));
            }

            // This launch's is undone
            launched.save().unwrap();
            forget_launch(&launched, launch).unwrap();
            let saved = VmMetadata::load_if_exists("vm").unwrap();
            match launch {
                Launch::New => assert!(saved.is_none()),
                Launch::Saved => {
                    let saved = saved.unwrap();
                    assert_eq!(
                        (&saved.created, saved.vfkit, saved.gvproxy, &*saved.state),
                        (
                            &launched.created,
                            TrackedProcess::NONE,
                            TrackedProcess::NONE,
                            "stopped"
                        )
                    );
                    VmMetadata::remove("vm");
                }
            }
        }
    }

    #[test]
    fn test_vm_metadata_roundtrip() {
        let meta = sample_vm_metadata("test-vm");
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let loaded: VmMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.name, "test-vm");
        assert_eq!(loaded.disk_image, "/tmp/disk.raw");
        assert_eq!(loaded.vcpus, 2);
        assert_eq!(loaded.memory_mb, 4096);
        assert_eq!(loaded.state, "running");
        assert!(!loaded.gui);
    }

    #[test]
    fn test_vm_metadata_save_load_remove() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("myvm.json");
        let meta = sample_vm_metadata("myvm");
        fs::write(&json_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
        let data = fs::read_to_string(&json_path).unwrap();
        let loaded: VmMetadata = serde_json::from_str(&data).unwrap();
        assert_eq!(loaded.name, "myvm");
        assert_eq!(loaded.ssh_port, 2222);
        fs::remove_file(&json_path).unwrap();
        assert!(!json_path.exists());
    }

    #[test]
    fn test_vm_metadata_list_from_dir() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            let meta = sample_vm_metadata(&format!("vm-{i}"));
            let path = dir.path().join(format!("vm-{i}.json"));
            fs::write(&path, serde_json::to_string(&meta).unwrap()).unwrap();
        }
        fs::write(dir.path().join("notes.txt"), "ignored").unwrap();

        let mut vms = Vec::new();
        for entry in fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(meta) = serde_json::from_str::<VmMetadata>(&data) {
                    vms.push(meta);
                }
            }
        }
        assert_eq!(vms.len(), 3);
        let mut names: Vec<_> = vms.iter().map(|v| v.name.clone()).collect();
        names.sort();
        assert_eq!(names, vec!["vm-0", "vm-1", "vm-2"]);
    }

    #[test]
    fn test_vm_metadata_is_alive_zero_pid() {
        let meta = sample_vm_metadata("dead-vm");
        assert!(!meta.is_alive());
    }
}
