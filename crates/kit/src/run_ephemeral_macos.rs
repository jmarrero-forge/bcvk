//! Ephemeral VM launch flow for macOS using vfkit + NBD EROFS over TCP.
//!
//! Boot flow (fully diskless):
//! 1. Mount container image overlay (`podman image mount`)
//! 2. Start bcvk-nbd server in TCP mode (port forwarded via gvproxy)
//! 3. Launch vfkit with EFI boot via NBD TCP + virtio-net (gvproxy)
//! 4. Wait for SSH and execute commands
//!
//! Common helpers (gvproxy, SSH, vfkit detection) live in vm_helpers.rs.

use std::fs;
use std::process::{Command, Stdio};
use std::time::Duration;

use color_eyre::{eyre::bail, eyre::Context as _, Result};
use tracing::{debug, info};

use crate::vm_helpers::{
    detect_machine_name, ensure_image_and_get_digest, find_available_ssh_port, is_machine_rootful,
    run_ssh_command, run_ssh_interactive, start_gvproxy, wait_for_ssh, TrackedProcess,
    VmMetadataStore,
};

/// Base directory for ephemeral VM state on macOS host.
pub fn ephemeral_base_dir() -> std::path::PathBuf {
    crate::vm_helpers::bcvk_base_dir().join("ephemeral")
}

// --- Data structures ---

/// Metadata for a running ephemeral VM, persisted as JSON for `ps` and `ssh`.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct EphemeralVmMetadata {
    /// VM name used as identifier for resource isolation.
    pub name: String,
    /// Container image reference used to boot the VM.
    pub image: String,
    /// The bcvk process running the VM, which holds its name from before
    /// anything is started under it, and cleans up after it.
    #[serde(default)]
    pub owner: TrackedProcess,
    /// The vfkit process.
    #[serde(default)]
    pub vfkit: TrackedProcess,
    /// The gvproxy network proxy process.
    #[serde(default)]
    pub gvproxy: TrackedProcess,
    /// Host-side SSH port forwarded to the VM.
    pub ssh_port: u16,
    /// Path to the SSH private key for this VM.
    pub ssh_key: String,
    /// Path to the serial console log file.
    pub serial_log: String,
    /// Path to the vfkit process log file.
    pub log_path: Option<String>,
    /// ISO 8601 timestamp when the VM was created.
    pub created: String,
    /// Systemd unit name of the bcvk-nbd server serving the rootfs.
    #[serde(default)]
    pub nbd_unit: Option<String>,
    /// NBD port allocated for this VM's rootfs.
    #[serde(default)]
    pub nbd_port: Option<u16>,
}

impl crate::vm_helpers::VmMetadataStore for EphemeralVmMetadata {
    fn vms_dir() -> std::path::PathBuf {
        ephemeral_base_dir().join("vms")
    }
    fn name(&self) -> &str {
        &self.name
    }
}

impl EphemeralVmMetadata {
    /// The metadata of a VM whose name this process reserves, see
    /// [`reserve_vm_name`]; `detached` adds the log of the bcvk process
    /// that --detach starts.
    pub(crate) fn reserved(name: &str, image: &str, detached: bool) -> Self {
        let base = ephemeral_base_dir();
        let path = |file: String| base.join(file).to_string_lossy().to_string();
        Self {
            name: name.to_string(),
            image: image.to_string(),
            owner: TrackedProcess::current(),
            vfkit: TrackedProcess::NONE,
            gvproxy: TrackedProcess::NONE,
            ssh_port: 0,
            ssh_key: path(format!("{name}-key")),
            serial_log: path(format!("{name}-serial.log")),
            log_path: detached.then(|| path(format!("bcvk-{name}.log"))),
            created: chrono::Utc::now().to_rfc3339(),
            nbd_unit: None,
            nbd_port: None,
        }
    }

    /// Whether the VM is running, or its bcvk process still starting it.
    pub fn is_alive(&self) -> bool {
        self.vfkit.is_running() || self.owner.is_running()
    }

    /// Whether this and `other` are the metadata of the same VM, rather
    /// than of two that had the same name one after the other.
    pub fn same_vm(&self, other: &Self) -> bool {
        self.name == other.name && self.created == other.created
    }
}

/// Options for launching an ephemeral VM via vfkit.
#[derive(clap::Parser, Debug)]
pub struct RunEphemeralOpts {
    /// Container image to boot
    pub image: String,
    #[clap(flatten)]
    pub size: crate::common_opts::VmSizeOpts,
    /// Generate a temporary SSH key pair for VM access
    #[clap(long = "ssh-keygen", short = 'K')]
    pub ssh_keygen: bool,
    /// Command(s) to execute via SSH after boot
    #[clap(long)]
    pub execute: Vec<String>,
    /// VM name for identification and resource isolation
    #[clap(long)]
    pub name: Option<String>,
    /// Additional kernel command line arguments
    #[clap(long = "karg")]
    pub kernel_args: Vec<String>,
    /// Display VM console in GUI window
    #[clap(long)]
    pub gui: bool,
    /// Run in background
    #[clap(long, short = 'd')]
    pub detach: bool,
    /// Enable debug mode (reserved for future use)
    #[clap(long)]
    pub debug: bool,
    /// Set on the bcvk process that --detach starts, which takes over
    /// the VM name (--name) that its parent reserved
    #[clap(long, hide = true, requires = "name")]
    pub detached_child: bool,
}

// --- RAII cleanup guard ---

struct VmCleanup {
    vfkit: TrackedProcess,
    gvproxy: TrackedProcess,
    nbd_unit: Option<String>,
    nbd_port: Option<u16>,
    image: String,
    image_mounted: bool,
    vm_name: String,
}

impl Drop for VmCleanup {
    fn drop(&mut self) {
        tracing::debug!("cleaning up VM processes...");
        // Stop the VM before the NBD server backing its root filesystem.
        // Its root is a read-only export, so there's no clean shutdown to
        // wait for.
        crate::vm_helpers::stop_vm_processes(self.vfkit, self.gvproxy, true);
        if let Some(ref name) = self.nbd_unit {
            crate::nbd_macos::stop_nbd_server(name, self.nbd_port);
        }
        // Release container image overlay mount
        if let Some(machine) = self
            .image_mounted
            .then(detect_machine_name)
            .and_then(Result::ok)
        {
            if let Err(e) = Command::new("podman")
                .args([
                    "machine",
                    "ssh",
                    &machine,
                    "--",
                    "podman",
                    "image",
                    "umount",
                    &self.image,
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
            {
                tracing::debug!("failed to umount image {}: {}", self.image, e);
            }
        }
        EphemeralVmMetadata::remove(&self.vm_name);
    }
}

// --- VM names ---

/// How many numbered variants of the default VM name to try.
const MAX_DEFAULT_NAME_TRIES: u32 = 100;

/// How long the bcvk process that --detach starts gets to take over the
/// VM's name.
const DETACHED_TAKEOVER_TIMEOUT: Duration = Duration::from_secs(30);

/// Reserve the VM's name for this process, saving its metadata: `--name`,
/// which no running VM may have (its NBD unit, SSH key and sockets are
/// named after it, so starting a second one would take them from the
/// first), or else one derived from the image digest, numbered when that
/// is taken. What a VM that is gone left under that name is released.
///
/// Under the VM names lock, so that runs at the same time get different
/// names.
fn reserve_vm_name(opts: &RunEphemeralOpts, digest_short: &str) -> Result<EphemeralVmMetadata> {
    let candidates: Vec<String> = match &opts.name {
        Some(name) => vec![name.clone()],
        None => {
            let base = format!("ephemeral-{}", &digest_short[..8.min(digest_short.len())]);
            (1..=MAX_DEFAULT_NAME_TRIES)
                .map(|i| match i {
                    1 => base.clone(),
                    i => format!("{base}-{i}"),
                })
                .collect()
        }
    };
    let _lock = EphemeralVmMetadata::lock()?;
    for name in candidates {
        crate::vm_helpers::gvproxy_socket_paths(&ephemeral_base_dir(), &name)?;
        if let Some(vm) = EphemeralVmMetadata::load_if_exists(&name)? {
            if vm.is_alive() {
                if opts.name.is_some() {
                    bail!(
                        "an ephemeral VM named '{name}' is already running; choose another \
                         --name, or remove it with `bcvk ephemeral rm-all`"
                    );
                }
                continue;
            }
            crate::ephemeral_macos::release(&vm);
        }
        let vm = EphemeralVmMetadata::reserved(&name, &opts.image, opts.detach);
        vm.save()?;
        return Ok(vm);
    }
    Err(color_eyre::eyre::eyre!(
        "{MAX_DEFAULT_NAME_TRIES} ephemeral VMs of this image are running; use --name"
    ))
}

/// Take over the VM name that the bcvk process which started this one
/// with --detach reserved, see [`run_detached`].
fn take_over_vm_name(name: &str) -> Result<EphemeralVmMetadata> {
    let parent = TrackedProcess::new(std::os::unix::process::parent_id());
    let _lock = EphemeralVmMetadata::lock()?;
    let mut vm = EphemeralVmMetadata::load_if_exists(name)?
        .filter(|vm| parent != TrackedProcess::NONE && vm.owner == parent)
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "VM name '{name}' isn't reserved by the bcvk process that started this one"
            )
        })?;
    vm.owner = TrackedProcess::current();
    vm.save()?;
    Ok(vm)
}

// --- Main entry point ---

/// Run an ephemeral VM from a container image.
///
pub fn run(opts: RunEphemeralOpts) -> Result<()> {
    if opts.gui && opts.detach {
        bail!("--gui and --detach cannot be used together (GUI requires foreground process)");
    }
    if let Some(name) = &opts.name {
        crate::vm_helpers::validate_vm_name(name)?;
        crate::vm_helpers::gvproxy_socket_paths(&ephemeral_base_dir(), name)?;
    }
    run_vfkit(opts)
}

/// Run an ephemeral VM using vfkit + EROFS over NBD (TCP transport).
fn run_vfkit(opts: RunEphemeralOpts) -> Result<()> {
    if opts.detach {
        return run_detached(&opts);
    }

    info!(image = %opts.image, "starting ephemeral VM on macOS (vfkit + NBD TCP)");

    let cache_base = ephemeral_base_dir();
    fs::create_dir_all(&cache_base)?;

    let machine = detect_machine_name()?;
    let rootful = is_machine_rootful(&machine);
    debug!(
        "podman machine '{}' ({})",
        machine,
        if rootful { "rootful" } else { "rootless" }
    );
    let digest = ensure_image_and_get_digest(&opts.image)?;
    let digest_short = &digest[..16.min(digest.len())];
    info!("image digest: {}...", digest_short);

    let vm = if opts.detached_child {
        // clap requires --name with it
        take_over_vm_name(opts.name.as_deref().unwrap_or_default())?
    } else {
        reserve_vm_name(&opts, digest_short)?
    };
    let vm_name = vm.name.clone();
    // Undoes everything from here on, the name reservation included, when
    // this function returns, however it does.
    let mut cleanup = VmCleanup {
        vfkit: TrackedProcess::NONE,
        gvproxy: TrackedProcess::NONE,
        nbd_unit: None,
        nbd_port: None,
        image: opts.image.clone(),
        image_mounted: false,
        vm_name: vm_name.clone(),
    };
    let ssh_key_path = std::path::PathBuf::from(&vm.ssh_key);

    let mut ssh_pubkey = String::new();
    if opts.ssh_keygen || !opts.execute.is_empty() {
        info!("generating SSH keypair...");
        ssh_pubkey = crate::vm_helpers::generate_ssh_keypair(&ssh_key_path)?;
    }

    let mut cmdline_parts: Vec<&str> = Vec::from(crate::kernel_cmdline::EPHEMERAL_KERNEL_ARGS);
    cmdline_parts.extend([
        // The QEMU backend adds this only for images with cloud-init
        // enabled, which it checks in the mounted image; it does nothing
        // on images without it. See there for why cloud-init must be off.
        "cloud-init=disabled",
        "console=hvc0",
        "root=/dev/vda2",
        "ro",
        "rootfstype=erofs",
        "console=tty0",
        "loglevel=4",
        "net.ifnames=0",
    ]);
    let user_args: Vec<&str> = opts.kernel_args.iter().map(|s| s.as_str()).collect();
    cmdline_parts.extend(&user_args);
    let cmdline = cmdline_parts.join(" ");

    // Deploy NBD server binary to podman machine (hash-checked, idempotent)
    crate::nbd_macos::deploy_nbd_server(&machine)?;

    // Get container image merged overlay path
    let merged_path = crate::nbd_macos::get_merged_path(&machine, rootful, &opts.image)?;
    cleanup.image_mounted = true;
    info!("overlay merged: {}", merged_path);

    let nbd_port = crate::nbd_macos::find_available_nbd_port();
    info!("NBD transport: TCP (port {})", nbd_port);
    let nbd_unit_name = crate::nbd_macos::nbd_unit_name(&vm_name);
    // Before starting it, as a failed start can leave the unit running (a
    // server still scanning the image when the wait for it times out, say)
    // and the port forwarded
    cleanup.nbd_unit = Some(nbd_unit_name.clone());
    cleanup.nbd_port = Some(nbd_port);
    crate::nbd_macos::start_nbd_server(
        &machine,
        &merged_path,
        &cmdline,
        &ssh_pubkey,
        nbd_port,
        &vm_name,
    )?;

    let vcpus = opts.size.vcpus();
    let memory_mb = opts.size.memory_mb()?;

    // gvproxy + vfkit (EFI boot)
    let (gvproxy_sock, services_sock) =
        crate::vm_helpers::gvproxy_socket_paths(&cache_base, &vm_name)?;
    let services_sock_str = services_sock.to_string_lossy().to_string();
    info!("starting gvproxy...");
    let gvproxy_child = start_gvproxy(&gvproxy_sock.to_string_lossy(), &services_sock_str)?;
    cleanup.gvproxy = TrackedProcess::new(gvproxy_child.id());

    let efi_store = cache_base.join(format!("{}-efi-vars", vm_name));
    let serial_log = std::path::PathBuf::from(&vm.serial_log);
    let vsock_sock = cache_base.join(format!("{}-vsock.sock", vm_name));
    let vfkit_config = crate::vm_helpers::VfkitConfig {
        vcpus,
        memory_mb,
        efi_store: &efi_store,
        boot_disk: format!(
            "nbd,uri=nbd://127.0.0.1:{}/,readonly,timeout=5000,deviceId=rootfs",
            nbd_port
        ),
        gvproxy_sock: &gvproxy_sock,
        serial_log: &serial_log,
        extra_devices: vec![format!(
            "virtio-vsock,port=9000,socketURL={},connect",
            vsock_sock.display()
        )],
        gui: opts.gui,
    };

    info!("launching vfkit...");
    let vfkit_log = cache_base.join(format!("{}-vfkit.log", vm_name));
    let mut vfkit_child = vfkit_config.spawn(Some(&vfkit_log))?;
    cleanup.vfkit = TrackedProcess::new(vfkit_child.id());

    let ssh_port = find_available_ssh_port();
    debug!("allocated SSH port: {}", ssh_port);

    let metadata = EphemeralVmMetadata {
        vfkit: cleanup.vfkit,
        gvproxy: cleanup.gvproxy,
        ssh_port,
        nbd_unit: Some(nbd_unit_name.clone()),
        nbd_port: Some(nbd_port),
        ..vm
    };
    metadata.save()?;

    if opts.ssh_keygen || !opts.execute.is_empty() {
        info!("setting up SSH port forwarding...");
        crate::vm_helpers::setup_ssh_port_forwarding(&services_sock_str, ssh_port)?;

        wait_for_ssh(ssh_port, &ssh_key_path, "root")?;

        if !opts.execute.is_empty() {
            for cmd_str in &opts.execute {
                info!("executing: {}", cmd_str);
                let status = run_ssh_command(ssh_port, &ssh_key_path, "root", cmd_str)?;
                if !status.success() {
                    bail!("command failed: {}", status);
                }
            }
            return Ok(());
        }

        info!(
            "SSH ready: ssh -p {} -i {} root@{}",
            ssh_port,
            ssh_key_path.display(),
            crate::vm_helpers::FORWARD_LOCALHOST
        );

        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            let status = run_ssh_interactive(ssh_port, &ssh_key_path, "root")?;
            let exit_code = status.code().unwrap_or(1);
            drop(cleanup);
            std::process::exit(exit_code);
        }
    }

    // No SSH: wait for vfkit to exit (GUI window closed or VM shutdown)
    let status = vfkit_child.wait()?;
    info!("vfkit exited: {}", status);
    Ok(())
}

/// Start a VM in the background: in a bcvk process of its own, which runs
/// it in the foreground and cleans up after it.
///
/// The VM's name is reserved before that process starts, and it takes the
/// name over, so that this one never writes the metadata the other may
/// have written already.
fn run_detached(opts: &RunEphemeralOpts) -> Result<()> {
    fs::create_dir_all(ephemeral_base_dir())?;
    let digest = ensure_image_and_get_digest(&opts.image)?;
    let digest_short = &digest[..16.min(digest.len())];
    let vm = reserve_vm_name(opts, digest_short)?;
    let started = start_detached_child(opts, &vm);
    if started.is_err() {
        if let Err(e) = release_reservation(&vm) {
            tracing::warn!("failed to release VM name '{}': {e}", vm.name);
        }
    }
    started?;
    println!("{}", vm.name);
    Ok(())
}

/// Remove the metadata of a VM whose name this process reserved, unless
/// another process took the name over since; if that process is gone
/// already, release what it left, see [`crate::ephemeral_macos::release`].
fn release_reservation(vm: &EphemeralVmMetadata) -> Result<()> {
    let _lock = EphemeralVmMetadata::lock()?;
    match EphemeralVmMetadata::load_if_exists(&vm.name)? {
        Some(cur) if cur.owner == vm.owner => EphemeralVmMetadata::remove(&vm.name),
        Some(cur) if cur.same_vm(vm) && !cur.is_alive() => crate::ephemeral_macos::release(&cur),
        _ => {}
    }
    Ok(())
}

/// Start the bcvk process running a detached VM, and wait for it to take
/// over the VM's name; on failure, that process is stopped.
fn start_detached_child(opts: &RunEphemeralOpts, vm: &EphemeralVmMetadata) -> Result<()> {
    let log_path = vm
        .log_path
        .as_deref()
        .ok_or_else(|| color_eyre::eyre::eyre!("no log file for VM '{}'", vm.name))?;
    let log_file = fs::File::create(log_path).with_context(|| format!("creating {log_path}"))?;
    let exe = std::env::current_exe()?;
    let child = Command::new(exe)
        .args(detached_child_args(opts, &vm.name))
        .stdin(Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .spawn()?;
    let child = TrackedProcess::new(child.id());
    let taken_over =
        crate::utils::wait_for_readiness(
            indicatif::ProgressBar::hidden(),
            "Waiting for the VM's bcvk process",
            || {
                if !child.is_running() {
                    bail!("bcvk failed to start the VM, see {log_path}");
                }
                Ok(EphemeralVmMetadata::load_if_exists(&vm.name)?
                    .is_some_and(|cur| cur.owner == child))
            },
            DETACHED_TAKEOVER_TIMEOUT,
            Duration::from_millis(50),
        );
    if taken_over.is_err() {
        crate::vm_helpers::terminate_process(child, "bcvk", Duration::ZERO, true);
    }
    taken_over.map(|_| ())
}

/// The command line of the bcvk process running a detached VM: the same
/// options, in the foreground, with an SSH key and the chosen name.
///
/// Built from the parsed options rather than by editing bcvk's own
/// arguments, which may come in any order or in combined (`-dK`) and
/// `--opt=value` forms.
fn detached_child_args(opts: &RunEphemeralOpts, vm_name: &str) -> Vec<String> {
    // No `..`, here or in the flattened option structs: a new option has
    // to be passed on, or deliberately not
    let RunEphemeralOpts {
        image,
        size:
            crate::common_opts::VmSizeOpts {
                itype,
                memory: crate::common_opts::MemoryOpts { memory },
                vcpus,
            },
        ssh_keygen: _,
        execute,
        name: _,
        kernel_args,
        gui: _,
        detach: _,
        debug,
        detached_child: _,
    } = opts;
    let mut args: Vec<String> = vec![
        "ephemeral".into(),
        "run".into(),
        "--detached-child".into(),
        "--ssh-keygen".into(),
        format!("--name={vm_name}"),
        format!("--memory={memory}"),
    ];
    if let Some(itype) = itype {
        args.push(format!("--itype={itype}"));
    }
    if let Some(vcpus) = vcpus {
        args.push(format!("--vcpus={vcpus}"));
    }
    args.extend(execute.iter().map(|cmd| format!("--execute={cmd}")));
    args.extend(kernel_args.iter().map(|karg| format!("--karg={karg}")));
    if *debug {
        args.push("--debug".into());
    }
    args.extend(["--".into(), image.clone()]);
    args
}

// --- macOS-specific helpers (pub for vfkit/ module) ---

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn test_detached_child_args() {
        for argv in [
            // -d before an option value, which inserting arguments in
            // front of the last one split from its option
            &["run", "quay.io/img:1", "-d", "--memory", "2G"][..],
            &[
                "run",
                "-dK",
                "--vcpus=3",
                "--itype",
                "u1.small",
                "--execute",
                "echo -d",
                "--karg=-x",
                "--karg",
                "console=ttyS0",
                "--debug",
                "--name",
                "mine",
                "--",
                "-image-",
            ],
        ] {
            let opts = RunEphemeralOpts::try_parse_from(argv).unwrap();
            assert!(opts.detach, "{argv:?}");
            let args = detached_child_args(&opts, "vm-1");
            assert_eq!(args[..2], ["ephemeral", "run"]);
            let child = RunEphemeralOpts::try_parse_from(
                std::iter::once("run").chain(args[2..].iter().map(|a| a.as_str())),
            )
            .unwrap();
            assert!(
                !child.detach && child.detached_child && child.ssh_keygen,
                "{args:?}"
            );
            assert_eq!(child.name.as_deref(), Some("vm-1"));
            assert_eq!(child.image, opts.image);
            assert_eq!(child.size.memory.memory, opts.size.memory.memory);
            assert_eq!(child.size.itype, opts.size.itype);
            assert_eq!(child.size.vcpus, opts.size.vcpus);
            assert_eq!(child.execute, opts.execute);
            assert_eq!(child.kernel_args, opts.kernel_args);
            assert_eq!(child.debug, opts.debug);
        }
    }

    fn parse_opts(args: &[&str]) -> RunEphemeralOpts {
        RunEphemeralOpts::try_parse_from(std::iter::once("run").chain(args.iter().copied()))
            .unwrap()
    }

    #[test]
    fn test_reserve_vm_name() {
        let _dir = crate::vm_helpers::use_test_base_dir();
        let digest = "0123456789abcdef";
        let reserve = |args: &[&str]| reserve_vm_name(&parse_opts(args), digest);

        // This process holds each name it reserves: the default one gets
        // numbered, a --name is refused
        let first = reserve(&["img"]).unwrap();
        assert_eq!(first.name, "ephemeral-01234567");
        assert_eq!(first.owner, TrackedProcess::current());
        assert!(first.log_path.is_none());
        let second = reserve(&["-d", "img"]).unwrap();
        assert_eq!(second.name, "ephemeral-01234567-2");
        assert!(second.log_path.is_some());
        for vm in [&first, &second] {
            assert!(EphemeralVmMetadata::load(&vm.name).unwrap().same_vm(vm));
        }
        let err = reserve(&["--name", "ephemeral-01234567", "img"]).unwrap_err();
        assert!(err.to_string().contains("already running"), "{err}");

        // A VM that is gone gives up its name
        EphemeralVmMetadata {
            owner: TrackedProcess::NONE,
            ..EphemeralVmMetadata::reserved("gone", "img", false)
        }
        .save()
        .unwrap();
        let mine = reserve(&["--name", "gone", "img"]).unwrap();
        assert_eq!(EphemeralVmMetadata::load("gone").unwrap().owner, mine.owner);

        // Metadata that can't be read isn't taken for a VM that is gone
        std::fs::write(
            EphemeralVmMetadata::metadata_path("legacy").unwrap(),
            r#"{"name": "legacy", "pid": 12}"#,
        )
        .unwrap();
        assert!(reserve(&["--name", "legacy", "img"]).is_err());
    }

    #[test]
    fn test_take_over_vm_name() {
        let _dir = crate::vm_helpers::use_test_base_dir();
        // Not reserved at all
        assert!(take_over_vm_name("vm").is_err());
        // Reserved by another process than this one's parent
        let mut vm = EphemeralVmMetadata::reserved("vm", "img", true);
        vm.save().unwrap();
        assert!(take_over_vm_name("vm").is_err());

        vm.owner = TrackedProcess::new(std::os::unix::process::parent_id());
        vm.save().unwrap();
        let taken = take_over_vm_name("vm").unwrap();
        assert_eq!(taken.owner, TrackedProcess::current());
        let saved = EphemeralVmMetadata::load("vm").unwrap();
        assert!(saved.same_vm(&vm));
        assert_eq!(saved.owner, TrackedProcess::current());
        // Only once
        assert!(take_over_vm_name("vm").is_err());
    }

    #[test]
    fn test_release_reservation() {
        let _dir = crate::vm_helpers::use_test_base_dir();
        let vm = EphemeralVmMetadata::reserved("vm", "img", true);
        vm.save().unwrap();
        release_reservation(&vm).unwrap();
        assert!(EphemeralVmMetadata::load_if_exists("vm").unwrap().is_none());

        // Taken over by a process that is still running, or by a new VM
        let child = EphemeralVmMetadata {
            owner: TrackedProcess::new(std::os::unix::process::parent_id()),
            ..vm.clone()
        };
        let new_vm = EphemeralVmMetadata {
            owner: TrackedProcess::NONE,
            created: "2999-01-01T00:00:00Z".into(),
            ..vm.clone()
        };
        for other in [&child, &new_vm] {
            other.save().unwrap();
            release_reservation(&vm).unwrap();
            assert_eq!(EphemeralVmMetadata::load("vm").unwrap().owner, other.owner);
        }
        // Taken over by a process that is gone
        EphemeralVmMetadata {
            owner: TrackedProcess::NONE,
            ..vm.clone()
        }
        .save()
        .unwrap();
        release_reservation(&vm).unwrap();
        assert!(EphemeralVmMetadata::load_if_exists("vm").unwrap().is_none());
    }

    #[test]
    fn test_reserved_metadata() {
        let vm = EphemeralVmMetadata::reserved("vm-1", "quay.io/img:1", true);
        // Held by this process, which is running
        assert_eq!(vm.owner, TrackedProcess::current());
        assert!(vm.is_alive());
        assert_eq!(vm.vfkit, TrackedProcess::NONE);
        let base = ephemeral_base_dir();
        assert_eq!(vm.ssh_key, base.join("vm-1-key").to_string_lossy());
        assert_eq!(
            vm.log_path.as_deref(),
            Some(&*base.join("bcvk-vm-1.log").to_string_lossy())
        );
        assert!(EphemeralVmMetadata::reserved("vm-1", "img", false)
            .log_path
            .is_none());

        assert!(vm.same_vm(&vm.clone()));
        let later = EphemeralVmMetadata {
            created: "2999-01-01T00:00:00Z".into(),
            ..vm.clone()
        };
        assert!(!vm.same_vm(&later));
        // Neither its bcvk process nor vfkit runs
        let gone = EphemeralVmMetadata {
            owner: TrackedProcess::NONE,
            ..vm
        };
        assert!(!gone.is_alive());
    }

    #[test]
    fn test_ephemeral_vm_metadata_roundtrip() {
        let meta = EphemeralVmMetadata {
            name: "test-vm".to_string(),
            image: "quay.io/fedora/fedora-bootc:42".to_string(),
            owner: TrackedProcess {
                pid: 12344,
                started_us: 1_777_000_000_000_000,
            },
            vfkit: TrackedProcess {
                pid: 12345,
                started_us: 1_777_000_000_000_000,
            },
            gvproxy: TrackedProcess {
                pid: 12346,
                started_us: 1_777_000_000_000_001,
            },
            ssh_port: 2222,
            ssh_key: "/tmp/test-key".to_string(),
            serial_log: "/tmp/test-serial.log".to_string(),
            log_path: Some("/tmp/test-vfkit.log".to_string()),
            created: "2026-01-01T00:00:00Z".to_string(),
            nbd_unit: Some("bcvk-nbd-test-vm".to_string()),
            nbd_port: Some(10841),
        };
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let loaded: EphemeralVmMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.name, "test-vm");
        assert_eq!(loaded.image, "quay.io/fedora/fedora-bootc:42");
        assert_eq!(loaded.owner, meta.owner);
        assert_eq!(loaded.vfkit, meta.vfkit);
        assert_eq!(loaded.gvproxy, meta.gvproxy);
        assert_eq!(loaded.nbd_unit.as_deref(), Some("bcvk-nbd-test-vm"));
        assert_eq!(loaded.ssh_port, 2222);
        assert_eq!(loaded.log_path.as_deref(), Some("/tmp/test-vfkit.log"));
    }

    #[test]
    fn test_ephemeral_vm_metadata_save_load_remove() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("roundtrip-vm.json");
        let meta = EphemeralVmMetadata {
            name: "roundtrip-vm".to_string(),
            image: "localhost/test:latest".to_string(),
            owner: TrackedProcess::NONE,
            vfkit: TrackedProcess::NONE,
            gvproxy: TrackedProcess::NONE,
            ssh_port: 2250,
            ssh_key: "/tmp/key".to_string(),
            serial_log: "/tmp/serial.log".to_string(),
            log_path: None,
            created: "2026-05-04T00:00:00Z".to_string(),
            nbd_unit: None,
            nbd_port: None,
        };
        fs::write(&json_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
        let data = fs::read_to_string(&json_path).unwrap();
        let loaded: EphemeralVmMetadata = serde_json::from_str(&data).unwrap();
        assert_eq!(loaded.name, "roundtrip-vm");
        assert_eq!(loaded.ssh_port, 2250);
        assert!(loaded.log_path.is_none());
        fs::remove_file(&json_path).unwrap();
        assert!(!json_path.exists());
    }

    #[test]
    fn test_ephemeral_vm_metadata_list_all_from_dir() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            let meta = EphemeralVmMetadata {
                name: format!("vm-{i}"),
                image: "test:latest".to_string(),
                owner: TrackedProcess::NONE,
                vfkit: TrackedProcess::NONE,
                gvproxy: TrackedProcess::NONE,
                ssh_port: 2222 + (i as u16),
                ssh_key: "/tmp/key".to_string(),
                serial_log: "/tmp/serial.log".to_string(),
                log_path: None,
                created: "2026-01-01T00:00:00Z".to_string(),
                nbd_unit: Some(format!("bcvk-nbd-vm-{i}")),
                nbd_port: Some(10800 + i as u16),
            };
            let path = dir.path().join(format!("vm-{i}.json"));
            fs::write(&path, serde_json::to_string(&meta).unwrap()).unwrap();
        }
        // Also write a non-json file that should be skipped
        fs::write(dir.path().join("README.txt"), "not json").unwrap();

        let mut vms = Vec::new();
        for entry in fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(meta) = serde_json::from_str::<EphemeralVmMetadata>(&data) {
                    vms.push(meta);
                }
            }
        }
        assert_eq!(vms.len(), 3);
        let mut names: Vec<_> = vms.iter().map(|v| v.name.clone()).collect();
        names.sort();
        assert_eq!(names, vec!["vm-0", "vm-1", "vm-2"]);
    }
}
