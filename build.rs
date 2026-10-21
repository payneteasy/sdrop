// Bakes into the binary the default trusted origin (SDROP_DEFAULT_ORIGIN at build time).
use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=SDROP_DEFAULT_ORIGIN");
    println!(
        "cargo:rustc-env=SDROP_DEFAULT_ORIGIN={}",
        env::var("SDROP_DEFAULT_ORIGIN").unwrap_or_default()
    );
}
