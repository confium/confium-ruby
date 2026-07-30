// build.rs — read the version of confium-core from Cargo.lock and emit
// it as a CARGO_RUSTC_ENV so lib.rs can read it at compile time.
//
// Note: cargo invokes build scripts with a custom cwd (the staging dir),
// so we cannot rely on `Path::new("Cargo.lock")` being present. Instead
// we walk up from CARGO_MANIFEST_DIR looking for a Cargo.toml that
// declares a [workspace] section. That Cargo.lock is the one we need.

use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = find_workspace_root(&manifest_dir);
    let lockfile_path = workspace_dir.join("Cargo.lock");
    let lockfile = fs::read_to_string(&lockfile_path).expect("could not read workspace Cargo.lock");

    let version = lockfile
        .lines()
        // find each `[[package]]` block then the `name = "..."` line inside
        .scan(String::new(), |state, line| {
            if line.trim().starts_with("[[package]]") {
                *state = String::new();
            } else {
                state.push_str(line);
                state.push('\n');
            }
            Some(state.clone())
        })
        .filter_map(|block| {
            let name = block.lines().find_map(|l| {
                let trimmed = l.trim();
                trimmed.strip_prefix("name = \"")?.strip_suffix('"').map(String::from)
            })?;
            let version = block.lines().find_map(|l| {
                let trimmed = l.trim();
                trimmed.strip_prefix("version = \"")?.strip_suffix('"').map(String::from)
            })?;
            Some((name, version))
        })
        .find(|(name, _)| name == "confium-core")
        .map(|(_, v)| v);

    match version {
        Some(v) => {
            println!("cargo:rerun-if-changed={}", lockfile_path.display());
            println!("cargo:rustc-env=CONFIUM_CORE_VERSION={v}");
        }
        None => panic!("confium-core not found in Cargo.lock"),
    }

    // Add rpath for librnp so the compiled bundle finds it at load time
    // without requiring DYLD_LIBRARY_PATH on every invocation.
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,/opt/homebrew/lib");
    }
}

/// Walk up the directory tree from `start` until we find a Cargo.toml
/// containing a `[workspace]` section. That directory is the workspace
/// root; its Cargo.lock is what we need.
fn find_workspace_root(start: &std::path::Path) -> PathBuf {
    let mut current = start.to_path_buf();
    loop {
        let candidate = current.join("Cargo.toml");
        if candidate.exists() {
            if let Ok(contents) = fs::read_to_string(&candidate) {
                if contents.contains("[workspace]") {
                    return current;
                }
            }
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => panic!("no workspace root found above {}", start.display()),
        }
    }
}
