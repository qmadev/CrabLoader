fn main() {
    println!("cargo::rustc-check-cfg=cfg(no_std)");
    println!("cargo::rustc-check-cfg=cfg(no_main)");

    let profile = std::env::var("PROFILE").unwrap();

    if profile == "release" {
        println!("cargo:rustc-link-arg=/ENTRY:ldrmain");
        println!("cargo:rustc-link-arg=/SUBSYSTEM:console");
        println!("cargo:rustc-cfg=no_main");
        println!("cargo:rustc-cfg=no_std");
    }
}
