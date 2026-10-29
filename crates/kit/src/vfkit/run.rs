//! vm run — Start a persistent VM from a container image or disk image.

use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use color_eyre::{eyre::bail, eyre::Context as _, Result};
use tracing::info;

use super::{VmMetadata, VmMetadataStore};
use crate::vm_helpers::{
    clear_xattr, detect_machine_name, ensure_image_and_get_digest, find_available_ssh_port,
    gvproxy_socket_paths, remove_file_if_exists, run_ssh_interactive, sanitize_vm_name,
    validate_vm_name, TrackedProcess,
};

/// Port mapping from host to VM (format: host_port:guest_port).
#[derive(Debug, Clone)]
pub struct PortMapping {
    /// Host-side port number.
    pub host_port: u16,
    /// Guest-side port number.
    pub guest_port: u16,
}

impl std::str::FromStr for PortMapping {
    type Err = color_eyre::Report;
    fn from_str(s: &str) -> Result<Self> {
        let (host_part, guest_part) = s.split_once(':').ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "Invalid port format '{}'. Expected format: host_port:guest_port",
                s
            )
        })?;
        let host_port = host_part
            .trim()
            .parse::<u16>()
            .map_err(|_| color_eyre::eyre::eyre!("Invalid host port '{}'", host_part))?;
        let guest_port = guest_part
            .trim()
            .parse::<u16>()
            .map_err(|_| color_eyre::eyre::eyre!("Invalid guest port '{}'", guest_part))?;
        Ok(PortMapping {
            host_port,
            guest_port,
        })
    }
}

/// Options for `vm run`.
#[derive(Parser, Debug)]
pub struct VmRunOpts {
    /// Container image or disk image path (.raw)
    #[clap(default_value = "")]
    pub image_or_disk: String,
    /// VM name (default: derived from image or disk filename)
    #[clap(long, short)]
    pub name: Option<String>,
    #[clap(flatten)]
    pub size: crate::common_opts::VmSizeOpts,
    /// Path to an existing SSH private key
    #[clap(long)]
    pub ssh_key: Option<String>,
    /// SSH port (default: auto-allocate)
    #[clap(long)]
    pub ssh_port: Option<u16>,
    /// Display VM console in GUI window
    #[clap(long)]
    pub gui: bool,
    /// Disk size for to-disk (e.g. "10G", "20G")
    #[clap(long, default_value = "20G")]
    pub disk_size: String,
    /// Installation options (filesystem, root-size, etc.)
    #[clap(flatten)]
    pub install: crate::install_options::InstallOptions,
    /// Replace existing VM with same name
    #[clap(long, short = 'R')]
    pub replace: bool,
    /// Port mapping from host to VM (format: host_port:guest_port, e.g. 8080:80)
    #[clap(long = "port", short = 'p', action = clap::ArgAction::Append)]
    pub port_mappings: Vec<PortMapping>,
    /// User-defined labels for organizing VMs (comma not allowed in labels)
    #[clap(long)]
    pub label: Vec<String>,
    /// Automatically SSH into the VM after creation
    #[clap(long)]
    pub ssh: bool,
    /// Wait for SSH to become available and verify connectivity (for testing)
    #[clap(long, conflicts_with = "ssh")]
    pub ssh_wait: bool,
    /// Keep the VM running in background after creation (always true for vfkit)
    #[clap(long, short = 'd')]
    pub detach: bool,
}

/// vCPUs of a persistent VM without --vcpus or --itype; ephemeral VMs
/// get all of the host's.
const DEFAULT_VCPUS: u32 = 2;

fn validate_labels(labels: &[String]) -> Result<()> {
    for label in labels {
        if label.contains(',') {
            bail!("Label '{}' contains comma which is not allowed", label);
        }
    }
    Ok(())
}

fn is_disk_path(input: &str) -> bool {
    let p = Path::new(input);
    p.extension()
        .map(|e| e == "raw" || e == "img" || e == "qcow2")
        .unwrap_or(false)
        || p.exists()
}

/// Create and launch a persistent VM.
pub fn run(opts: VmRunOpts) -> Result<()> {
    if opts.image_or_disk.is_empty() {
        bail!("container image or disk path required");
    }
    validate_labels(&opts.label)?;

    let disk_input = is_disk_path(&opts.image_or_disk);
    let vm_name = choose_vm_name(&opts, disk_input)?;

    let existing = VmMetadata::load_if_exists(&vm_name)?;
    if existing.is_some() && !opts.replace {
        bail!(
            "VM '{}' already exists. Use --replace to overwrite, or --name to choose a different name.",
            vm_name
        );
    }

    // Check what can be checked before replacing a VM, so that a run that
    // would fail doesn't remove it
    let disk_path = if disk_input {
        // Absolute, so that later commands find it from any directory
        fs::canonicalize(&opts.image_or_disk)
            .with_context(|| format!("disk image not found: {}", opts.image_or_disk))?
    } else {
        crate::to_disk_macos::vms_dir().join(format!("{}.raw", vm_name))
    };
    let disk_path_str = disk_path.to_string_lossy().to_string();
    super::check_disk_not_in_use(&vm_name, &disk_path_str)?;
    let explicit_ssh_key = opts
        .ssh_key
        .as_deref()
        .map(|p| {
            // Absolute, so that later commands find it from any directory
            fs::canonicalize(p)
                .map(|key| key.to_string_lossy().to_string())
                .with_context(|| format!("SSH key not found: {p}"))
        })
        .transpose()?;
    let vcpus = opts.size.vcpus_or(DEFAULT_VCPUS);
    let memory_mb = opts.size.memory_mb()?;

    // A disk image's key can be looked for now; one made from a container
    // image comes with its disk
    let ssh_key = match explicit_ssh_key {
        None if disk_input => Some(find_ssh_key(&disk_path_str)?),
        key => key,
    };
    // The base disk too, installing the image into it being the step most
    // likely to fail. A disk of bcvk's left without its VM is used as it
    // is, unless --replace.
    let base_disk = if disk_input || (!opts.replace && disk_path.exists()) {
        None
    } else {
        let image = &opts.image_or_disk;
        let machine = detect_machine_name()?;
        let digest = ensure_image_and_get_digest(image)?;
        Some(crate::to_disk_macos::find_or_create_base_disk(
            image,
            &digest,
            &opts.install,
            &opts.disk_size,
            &machine,
            &None,
            &[],
        )?)
    };

    let vms_dir = VmMetadata::vms_dir();
    fs::create_dir_all(&vms_dir)?;

    let efi_store = vms_dir.join(format!("{}-efi-vars", vm_name));
    let serial_log = vms_dir.join(format!("{}-serial.log", vm_name));

    let ssh_port = opts.ssh_port.unwrap_or_else(find_available_ssh_port);
    info!("SSH port: {}", ssh_port);

    let mut metadata = VmMetadata {
        name: vm_name.clone(),
        image: (!disk_input).then(|| opts.image_or_disk.clone()),
        disk_image: disk_path_str.clone(),
        vfkit: TrackedProcess::NONE,
        gvproxy: TrackedProcess::NONE,
        ssh_port,
        // Known once the disk is there
        ssh_key: String::new(),
        vcpus,
        memory_mb,
        efi_store: efi_store.to_string_lossy().to_string(),
        serial_log: serial_log.to_string_lossy().to_string(),
        gui: opts.gui,
        created: chrono::Utc::now().to_rfc3339(),
        state: "running".to_string(),
        labels: opts.label.clone(),
        port_mappings: opts
            .port_mappings
            .iter()
            .map(|pm| (pm.host_port, pm.guest_port))
            .collect(),
    };
    // Under the VMs lock, where what was checked above may have changed:
    // another bcvk command may have created, replaced or removed the VM,
    // or its disk, meanwhile
    let prepare = |meta: &mut VmMetadata| -> Result<()> {
        prepare_disk(
            &vm_name,
            existing.as_ref(),
            disk_input,
            &disk_path,
            base_disk.as_deref(),
            opts.replace,
        )?;
        clear_xattr(&disk_path);
        meta.ssh_key = match &ssh_key {
            Some(key) => key.clone(),
            None => find_ssh_key(&disk_path_str)?,
        };
        Ok(())
    };
    super::launch(&mut metadata, super::Launch::New, prepare)?;
    let ssh_key_path = &metadata.ssh_key;
    let key_path = Path::new(ssh_key_path);

    println!("VM '{}' is running", vm_name);
    println!(
        "  ssh -p {} -i {} root@{}",
        ssh_port,
        ssh_key_path,
        crate::vm_helpers::FORWARD_LOCALHOST
    );
    println!();
    println!("To connect:  bcvk vm ssh {}", vm_name);
    println!("To stop:     bcvk vm stop {}", vm_name);

    if opts.ssh_wait {
        println!("Ready; use bcvk vm ssh to connect");
        return Ok(());
    }
    if opts.ssh {
        let status = run_ssh_interactive(ssh_port, key_path, "root")?;
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

/// Replace the VM that `vm run` found under the name, if any, and create
/// the new VM's disk from `base_disk` unless `disk` is the user's own,
/// see [`replace_existing`] and [`create_disk`]. Under the VMs lock.
fn prepare_disk(
    name: &str,
    existing: Option<&VmMetadata>,
    disk_input: bool,
    disk: &Path,
    base_disk: Option<&Path>,
    replace: bool,
) -> Result<()> {
    replace_existing(name, existing, disk_input, &disk.to_string_lossy())?;
    if let Some(base_disk) = base_disk {
        create_disk(name, base_disk, disk, replace)?;
    }
    Ok(())
}

/// Stop and remove the VM that `vm run --replace` replaces, `existing`
/// as `vm run` found it before. Under the VMs lock.
///
/// Fails if the VM saved under the name isn't that one: another bcvk
/// command created it meanwhile, and only the VM the user saw is replaced.
/// Fails too if its disk would go while another running VM uses it.
fn replace_existing(
    name: &str,
    existing: Option<&VmMetadata>,
    disk_input: bool,
    new_disk: &str,
) -> Result<()> {
    // None: there was none, or another command removed it meanwhile
    let Some(current) = VmMetadata::load_if_exists(name)? else {
        return Ok(());
    };
    if existing.is_none_or(|existing| existing.created != current.created) {
        bail!("VM '{name}' was created by another bcvk command meanwhile");
    }
    let keep_disk = replacement_keeps_disk(&current, disk_input, new_disk);
    if !keep_disk {
        // Another VM may have been started off it while this one was
        // stopped
        super::check_disk_not_in_use(name, &current.disk_image)?;
    }
    info!("replacing existing VM '{}'", name);
    // A disk that goes has nothing worth a clean shutdown
    current.stop_processes(!keep_disk);
    if !keep_disk {
        super::rm::remove_own_disk(&current);
    }
    VmMetadata::remove(name);
    Ok(())
}

/// Create the disk of VM `name` at `disk` from the base disk, with the
/// base disk's SSH key. Under the VMs lock, once no VM of that name is
/// left.
///
/// `vm run` found no disk there earlier, or was given --replace: a disk
/// there now without --replace is another bcvk command's, so this fails
/// rather than remove it. With --replace, the disk goes unless a running
/// VM of another name uses it.
fn create_disk(name: &str, base_disk: &Path, disk: &Path, replace: bool) -> Result<()> {
    if disk.exists() {
        if !replace {
            bail!(
                "disk image {} was created by another bcvk command meanwhile",
                disk.display()
            );
        }
        super::check_disk_not_in_use(name, &disk.to_string_lossy())?;
    }
    let key_path = PathBuf::from(format!("{}.key", disk.display()));
    let key_pub_path = PathBuf::from(format!("{}.pub", key_path.display()));
    remove_file_if_exists(disk);
    remove_file_if_exists(&key_path);
    remove_file_if_exists(&key_pub_path);
    info!("creating disk image for VM '{}'...", name);
    crate::to_disk_macos::clone_base_disk(base_disk, disk)?;

    let base_key = PathBuf::from(format!("{}.key", base_disk.display()));
    if base_key.exists() {
        fs::copy(&base_key, &key_path)?;
        let base_pub = PathBuf::from(format!("{}.pub", base_key.display()));
        if base_pub.exists() {
            fs::copy(&base_pub, &key_pub_path)?;
        }
    }
    Ok(())
}

/// Whether the disk of a VM that `vm run --replace` replaces stays: one
/// bcvk made from an image goes with its VM, unless the new VM boots
/// from it; one of the user's own stays.
fn replacement_keeps_disk(existing: &VmMetadata, disk_input: bool, new_disk: &str) -> bool {
    !existing.has_own_disk() || (disk_input && existing.disk_image == new_disk)
}

/// The VM's name: `--name`, or else derived from the image name or the
/// disk's file name.
fn choose_vm_name(opts: &VmRunOpts, disk_input: bool) -> Result<String> {
    let name = match &opts.name {
        Some(name) => name.clone(),
        None if disk_input => {
            let stem = Path::new(&opts.image_or_disk)
                .file_stem()
                .map(|s| sanitize_vm_name(&s.to_string_lossy()))
                .unwrap_or_default();
            if stem.is_empty() {
                "vm".to_string()
            } else {
                stem
            }
        }
        None => {
            let name = sanitize_vm_name(&opts.image_or_disk);
            if name.is_empty() {
                bail!("could not derive VM name from image. Use --name to specify one.");
            }
            name
        }
    };
    validate_vm_name(&name)?;
    gvproxy_socket_paths(&VmMetadata::vms_dir(), &name)?;
    Ok(name)
}

/// The SSH key of a VM without --ssh-key.
fn find_ssh_key(disk_path: &str) -> Result<String> {
    let auto_key = format!("{}.key", disk_path);
    if Path::new(&auto_key).exists() {
        info!("using auto-generated SSH key: {}", auto_key);
        return Ok(auto_key);
    }
    let home = dirs::home_dir()
        .ok_or_else(|| color_eyre::eyre::eyre!("cannot determine home directory"))?;
    for name in &["id_ed25519", "id_rsa"] {
        let path = home.join(".ssh").join(name);
        if path.exists() {
            return Ok(path.to_string_lossy().to_string());
        }
    }
    Err(color_eyre::eyre::eyre!(
        "no SSH key found. Specify with --ssh-key"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_existing() {
        let _dir = crate::vm_helpers::use_test_base_dir();
        let old = crate::vfkit::tests::sample_vm_metadata("vm");
        let other = VmMetadata {
            created: "2999-01-01T00:00:00Z".into(),
            ..old.clone()
        };
        let disk = old.disk_image.clone();
        let replace = |existing: Option<&VmMetadata>| {
            replace_existing("vm", existing, false, &disk)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        };

        // Nothing to replace, whether there was or not
        assert_eq!(replace(None), "");
        assert_eq!(replace(Some(&old)), "");
        // The VM found earlier goes
        old.save().unwrap();
        assert_eq!(replace(Some(&old)), "");
        assert!(VmMetadata::load_if_exists("vm").unwrap().is_none());
        // One created since then stays
        other.save().unwrap();
        for existing in [None, Some(&old)] {
            assert!(replace(existing).contains("created by another"));
            assert_eq!(VmMetadata::load("vm").unwrap().created, other.created);
        }
    }

    #[test]
    fn test_create_disk_keeps_others_disks() {
        let _dir = crate::vm_helpers::use_test_base_dir();
        let disk = VmMetadata::vms_dir().join("vm.raw");
        fs::create_dir_all(disk.parent().unwrap()).unwrap();
        fs::write(&disk, "in use").unwrap();
        let base = Path::new("/nonexistent/base.raw");
        let create = |replace| {
            create_disk("vm", base, &disk, replace)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        };

        // A disk that appeared since vm run looked: another command's
        assert!(create(false).contains("created by another"));
        // With --replace too, while another VM runs from it
        VmMetadata {
            disk_image: disk.to_string_lossy().into_owned(),
            vfkit: TrackedProcess::current(),
            ..crate::vfkit::tests::sample_vm_metadata("other")
        }
        .save()
        .unwrap();
        assert!(create(true).contains("in use by the running VM 'other'"));
        assert_eq!(fs::read_to_string(&disk).unwrap(), "in use");
    }

    #[test]
    fn test_replace_keeps_disk_in_use() {
        let dir = crate::vm_helpers::use_test_base_dir();
        let vms_dir = VmMetadata::vms_dir();
        fs::create_dir_all(&vms_dir).unwrap();
        let disk = vms_dir.join("x.raw");
        let key = vms_dir.join("x.raw.key");
        let base = dir.path().join("base.raw");
        let user_disk = dir.path().join("user.raw");
        fs::write(&disk, "old").unwrap();
        fs::write(&key, "old").unwrap();
        fs::write(&base, "new").unwrap();
        let x = VmMetadata {
            disk_image: disk.to_string_lossy().into_owned(),
            ..crate::vfkit::tests::sample_vm_metadata("x")
        };
        x.save().unwrap();
        // y, started off x's disk while x was stopped
        let save_y = |vfkit| {
            VmMetadata {
                name: "y".into(),
                vfkit,
                ..x.clone()
            }
            .save()
            .unwrap()
        };
        save_y(TrackedProcess::current());

        // Neither replacing x from an image nor from another disk removes it
        for (disk_input, new_disk, base_disk) in [
            (false, &disk, Some(base.as_path())),
            (true, &user_disk, None),
        ] {
            let err = prepare_disk("x", Some(&x), disk_input, new_disk, base_disk, true)
                .unwrap_err()
                .to_string();
            assert!(err.contains("in use by the running VM 'y'"), "{err}");
            assert_eq!(fs::read_to_string(&disk).unwrap(), "old");
            assert!(key.exists());
            assert_eq!(VmMetadata::load("x").unwrap().created, x.created);
        }
        // Once y stopped, it does
        save_y(TrackedProcess::NONE);
        prepare_disk("x", Some(&x), false, &disk, Some(&base), true).unwrap();
        assert_eq!(fs::read_to_string(&disk).unwrap(), "new");
        assert!(!key.exists());
        assert!(VmMetadata::load_if_exists("x").unwrap().is_none());
    }

    #[test]
    fn test_replacement_keeps_disk() {
        let own = VmMetadata::vms_dir().join("vm.raw");
        let own = own.to_str().unwrap();
        let user = "/data/vm.raw";
        for (old_disk, disk_input, new_disk, keeps) in [
            // From an image again: the same path, but a new disk
            (own, false, own, false),
            (own, true, own, true),
            (own, true, user, false),
            (user, false, own, true),
            (user, true, user, true),
            (user, true, "/data/other.raw", true),
        ] {
            let existing = VmMetadata {
                disk_image: old_disk.to_string(),
                ..crate::vfkit::tests::sample_vm_metadata("vm")
            };
            assert_eq!(
                replacement_keeps_disk(&existing, disk_input, new_disk),
                keeps,
                "{old_disk} {disk_input} {new_disk}"
            );
        }
    }
}
