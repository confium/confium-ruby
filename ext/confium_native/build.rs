// build.rs — read the version of confium-core from Cargo.lock and emit
// it as a CARGO_RUSTC_ENV so lib.rs can read it at compile time.

use std::fs;

fn main() {
    let lockfile = fs::read_to_string("../Cargo.lock")
        .or_else(|_| fs::read_to_string("Cargo.lock"))
        .expect("could not read Cargo.lock");

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
            println!("cargo:rerun-if-changed=../Cargo.lock");
            println!("cargo:rerun-if-changed=Cargo.lock");
            println!("cargo:rustc-env=CONFIUM_CORE_VERSION={v}");
        }
        None => {
            panic!("confium-core not found in Cargo.lock");
        }
    }
}
