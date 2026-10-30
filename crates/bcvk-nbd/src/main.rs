mod dir_walk;
mod erofs;
mod fat32;
mod gpt;
mod initramfs;
pub mod nbd;
pub mod regions;

use std::net::TcpListener;
use std::path::{Path, PathBuf};

use cap_std::fs::Dir;

use regions::Region;

struct Args {
    dir: PathBuf,
    port: u16,
    cmdline: String,
    ssh_pubkey: Option<String>,
    vsock: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        dir: PathBuf::new(),
        port: 10809,
        cmdline: String::new(),
        ssh_pubkey: None,
        vsock: false,
    };

    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--dir" => {
                args.dir = PathBuf::from(argv.next().unwrap_or_else(|| {
                    eprintln!("--dir requires a value");
                    std::process::exit(1);
                }));
            }
            "--port" => {
                let val = argv.next().unwrap_or_else(|| {
                    eprintln!("--port requires a value");
                    std::process::exit(1);
                });
                args.port = val.parse().unwrap_or_else(|_| {
                    eprintln!("--port: invalid number: {val}");
                    std::process::exit(1);
                });
            }
            "--cmdline" => {
                args.cmdline = argv.next().unwrap_or_else(|| {
                    eprintln!("--cmdline requires a value");
                    std::process::exit(1);
                });
            }
            "--ssh-pubkey" => {
                args.ssh_pubkey = Some(argv.next().unwrap_or_else(|| {
                    eprintln!("--ssh-pubkey requires a value");
                    std::process::exit(1);
                }));
            }
            "--vsock" => {
                args.vsock = true;
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!(
                    "usage: bcvk-nbd --dir DIR --port PORT --cmdline CMDLINE [--ssh-pubkey KEY] [--vsock]"
                );
                std::process::exit(1);
            }
        }
    }

    if args.dir.as_os_str().is_empty() {
        eprintln!("--dir is required");
        std::process::exit(1);
    }
    if args.cmdline.is_empty() {
        eprintln!("--cmdline is required");
        std::process::exit(1);
    }

    args
}

/// Where the image's kernels are, relative to its root.
const MODULES_DIR: &str = "usr/lib/modules";
/// Where to look for the GRUB EFI binary, relative to the image's root.
const GRUB_SEARCH_DIR: &str = "usr/lib";
/// GRUB EFI binary names, in order of preference.
const GRUB_NAMES: [&str; 2] = ["grubaa64.efi", "grubx64.efi"];

// The boot files are looked up through `root`, the image directory opened
// with cap-std, which resolves symlinks only within the image and fails on
// one leading out of it (an absolute one, say, which the server would
// otherwise resolve on the podman machine and export). So a path found
// this way names the same file when the server later opens it under the
// image directory, and it can't make the server export a file of the
// podman machine.

/// Whether `path` is a regular file in the image (following symlinks
/// within it).
fn is_image_file(root: &Dir, path: &Path) -> bool {
    root.metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

/// The kernel and initramfs, relative to the image root.
fn find_kernel_dir(root: &Dir) -> Option<(PathBuf, PathBuf)> {
    let modules = Path::new(MODULES_DIR);
    for entry in root.read_dir(modules).ok()?.flatten() {
        let kdir = modules.join(entry.file_name());
        let vmlinuz = kdir.join("vmlinuz");
        let initramfs = kdir.join("initramfs.img");
        if is_image_file(root, &vmlinuz) && is_image_file(root, &initramfs) {
            return Some((vmlinuz, initramfs));
        }
    }
    None
}

/// The GRUB EFI binary, relative to the image root.
///
/// Only real directories are searched, so a symlink to a directory can't
/// lead the search out of the image or around in a loop.
fn find_grub(root: &Dir) -> Option<PathBuf> {
    fn walk(root: &Dir, path: &Path, target: &str) -> Option<PathBuf> {
        for entry in root.read_dir(path).ok()?.flatten() {
            let p = path.join(entry.file_name());
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => {
                    if let Some(found) = walk(root, &p, target) {
                        return Some(found);
                    }
                }
                Ok(_) if entry.file_name().to_str() == Some(target) && is_image_file(root, &p) => {
                    return Some(p);
                }
                _ => {}
            }
        }
        None
    }
    GRUB_NAMES
        .iter()
        .find_map(|name| walk(root, Path::new(GRUB_SEARCH_DIR), name))
}

fn file_size(path: &std::path::Path) -> u64 {
    match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("cannot stat {}: {}", path.display(), e);
            std::process::exit(1);
        }
    }
}

fn build_disk(args: &Args) -> (Vec<Region>, u64) {
    let root_dir = match Dir::open_ambient_dir(&args.dir, cap_std::ambient_authority()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("failed to open directory {:?}: {}", args.dir, e);
            std::process::exit(1);
        }
    };

    let walk = match dir_walk::walk_directory(&root_dir, &args.dir) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("failed to walk directory: {e}");
            std::process::exit(1);
        }
    };

    let erofs_layout = match erofs::build_erofs(&walk) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to build EROFS: {e}");
            std::process::exit(1);
        }
    };

    let erofs_regions =
        match regions::consolidate_regions(erofs::build_erofs_regions(&erofs_layout, &walk)) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("failed to read small files: {e}");
                std::process::exit(1);
            }
        };

    let (kernel_path, initrd_path) = match find_kernel_dir(&root_dir) {
        Some((kernel, initrd)) => (args.dir.join(kernel), args.dir.join(initrd)),
        None => {
            eprintln!(
                "kernel/initramfs not found in {}/{MODULES_DIR}/",
                args.dir.display()
            );
            std::process::exit(1);
        }
    };

    let grub_path = match find_grub(&root_dir) {
        Some(p) => args.dir.join(p),
        None => {
            eprintln!(
                "{} not found in {}/{GRUB_SEARCH_DIR}/",
                GRUB_NAMES.join("/"),
                args.dir.display()
            );
            std::process::exit(1);
        }
    };

    let kernel_size = file_size(&kernel_path);
    let initrd_size = file_size(&initrd_path);
    let grub_size = file_size(&grub_path);

    let grub_cfg = format!(
        "set timeout=0\nset default=0\nmenuentry \"bcvk\" {{\n  linux /boot/vmlinuz {}\n  initrd /boot/initrd.img\n}}\n",
        args.cmdline
    );

    let units_cpio = initramfs::build_units_cpio();
    let ssh_cpio = args.ssh_pubkey.as_deref().map(initramfs::build_ssh_cpio);

    let (initrd_parts, initrd_total) =
        fat32::build_initrd_regions(&initrd_path, initrd_size, &units_cpio, ssh_cpio.as_deref());

    let (esp_regions, esp_size) = fat32::build_esp_regions(
        &grub_path,
        grub_size,
        grub_cfg.as_bytes(),
        &kernel_path,
        kernel_size,
        initrd_parts,
        initrd_total,
    );

    match gpt::build_gpt_disk(
        esp_regions,
        esp_size,
        erofs_regions,
        erofs_layout.total_size,
    ) {
        Ok(disk) => (disk.regions, disk.total_size),
        Err(e) => {
            eprintln!("failed to build GPT disk: {e}");
            std::process::exit(1);
        }
    }
}

fn main() {
    let args = parse_args();
    let vsock = args.vsock;
    let port = args.port;

    eprintln!("bcvk-nbd: scanning {}...", args.dir.display());
    let (regions, total_size) = build_disk(&args);
    eprintln!(
        "bcvk-nbd: disk ready ({} regions, {} bytes)",
        regions.len(),
        total_size
    );

    let device = nbd::RegionBlockDevice::new(regions, total_size);

    if vsock {
        eprintln!("bcvk-nbd: listening on vsock port {port}");
        nbd::serve_vsock(port as u32, device);
    } else {
        let listener = TcpListener::bind(("0.0.0.0", port)).unwrap_or_else(|e| {
            eprintln!("bcvk-nbd: failed to bind TCP port {port}: {e}");
            std::process::exit(1);
        });
        eprintln!("bcvk-nbd: listening on TCP port {port}");
        nbd::serve_tcp(listener, device);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// An image directory with the given files and symlinks, and a regular
    /// file outside of it, at `outside`.
    fn image(files: &[&str], symlinks: &[(&str, &str)]) -> (tempfile::TempDir, Dir) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("outside"), b"secret").unwrap();
        let root = tmp.path().join("root");
        for f in files {
            let p = root.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, b"data").unwrap();
        }
        for (link, target) in symlinks {
            let p = root.join(link);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            let target = target.replace("@OUTSIDE@", &tmp.path().join("outside").to_string_lossy());
            symlink(target, p).unwrap();
        }
        let dir = Dir::open_ambient_dir(&root, cap_std::ambient_authority()).unwrap();
        (tmp, dir)
    }

    const K: &str = "usr/lib/modules/6.1";

    #[test]
    fn test_find_kernel_dir() {
        let vmlinuz = format!("{K}/vmlinuz");
        let initramfs = format!("{K}/initramfs.img");
        let expected = Some((PathBuf::from(&vmlinuz), PathBuf::from(&initramfs)));
        for (files, symlinks, expected) in [
            (
                vec![vmlinuz.as_str(), initramfs.as_str()],
                vec![],
                expected.clone(),
            ),
            // A symlink within the image is fine
            (
                vec![initramfs.as_str(), "boot/vmlinuz-6.1"],
                vec![(vmlinuz.as_str(), "../../../../boot/vmlinuz-6.1")],
                expected.clone(),
            ),
            // One leading out of the image is not, absolute or relative
            (
                vec![initramfs.as_str()],
                vec![(vmlinuz.as_str(), "@OUTSIDE@")],
                None,
            ),
            (
                vec![initramfs.as_str()],
                vec![(vmlinuz.as_str(), "../../../../../outside")],
                None,
            ),
            (vec![initramfs.as_str()], vec![], None),
        ] {
            let (_tmp, root) = image(&files, &symlinks);
            assert_eq!(find_kernel_dir(&root), expected, "{files:?} {symlinks:?}");
        }
    }

    #[test]
    fn test_find_grub() {
        let grub = "usr/lib/efi/grub2/EFI/fedora/grubx64.efi";
        for (files, symlinks, expected) in [
            (vec![grub], vec![], Some(grub)),
            // grubaa64.efi wins
            (
                vec![grub, "usr/lib/efi/grubaa64.efi"],
                vec![],
                Some("usr/lib/efi/grubaa64.efi"),
            ),
            // A symlink to a file outside, and a loop, are skipped
            (
                vec![],
                vec![
                    ("usr/lib/a/grubx64.efi", "@OUTSIDE@"),
                    ("usr/lib/loop", "."),
                ],
                None,
            ),
            // Symlinked directories aren't searched
            (
                vec!["usr/share/grubx64.efi"],
                vec![("usr/lib/share", "../share")],
                None,
            ),
        ] {
            let (_tmp, root) = image(&files, &symlinks);
            assert_eq!(
                find_grub(&root),
                expected.map(PathBuf::from),
                "{files:?} {symlinks:?}"
            );
        }
    }
}
