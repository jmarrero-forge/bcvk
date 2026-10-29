//! Persistent VM management for macOS using vfkit + EFI boot.
//!
//! Subcommands mirror the Linux libvirt/ module structure:
//! run, list, ssh, stop, start, rm, rm-all, inspect

use std::path::{Path, PathBuf};
use std::process::Child;

use clap::Subcommand;
use color_eyre::Result;
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
}

/// Start gvproxy and vfkit for a persistent VM, forward its ports and wait
/// for SSH; on failure, nothing is left running.
///
/// Returns the vfkit and gvproxy processes.
pub(crate) fn launch(meta: &VmMetadata) -> Result<(Child, Child)> {
    use crate::vm_helpers::{
        expose_port, gvproxy_socket_paths, setup_ssh_port_forwarding, start_gvproxy,
        stop_vm_processes, wait_for_ssh, FORWARD_ALL_INTERFACES, GVPROXY_VM_IP,
    };

    let (gvproxy_sock, services_sock) = gvproxy_socket_paths(&VmMetadata::vms_dir(), &meta.name)?;
    let services_sock = services_sock.to_string_lossy().to_string();

    info!("starting gvproxy...");
    let gvproxy = start_gvproxy(&gvproxy_sock.to_string_lossy(), &services_sock)?;

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
    let vfkit = match config.spawn(None) {
        Ok(child) => child,
        Err(e) => {
            stop_vm_processes(
                TrackedProcess::NONE,
                TrackedProcess::new(gvproxy.id()),
                true,
            );
            return Err(e);
        }
    };

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
    if let Err(e) = connect() {
        stop_vm_processes(
            TrackedProcess::new(vfkit.id()),
            TrackedProcess::new(gvproxy.id()),
            true,
        );
        return Err(e);
    }
    Ok((vfkit, gvproxy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sample_vm_metadata(name: &str) -> VmMetadata {
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
