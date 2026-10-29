//! Build script: copy cross-compiled NBD server binary into OUT_DIR for include_bytes!.

/// Where `make nbd-server` puts the NBD server, relative to the workspace root.
const NBD_SERVER_PATH: &str = "target/nbd-server/bcvk-nbd";

fn main() {
    // Only the vfkit backend embeds the NBD server (nbd_macos.rs is
    // cfg-gated), so other targets don't need it. Pointing
    // rerun-if-changed at a file that doesn't exist would make cargo
    // rerun this script, and rebuild bcvk, on every build.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let nbd_src = std::path::Path::new(&manifest_dir)
        .join("../..")
        .join(NBD_SERVER_PATH);
    println!("cargo:rerun-if-changed={}", nbd_src.display());
    let dest = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("bcvk-nbd");
    if let Err(e) = std::fs::copy(&nbd_src, &dest) {
        panic!(
            "copying {}: {e}; the macOS build embeds the NBD server, which is \
             cross-compiled for the podman machine: build with `just build` \
             (or run `make nbd-server` first)",
            nbd_src.display()
        );
    }
}
