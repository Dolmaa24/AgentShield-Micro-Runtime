//! Builds the Swift Virtualization.framework helper on macOS.
//!
//! Absent Swift, or on any other platform, this does nothing and the VM
//! runtime reports itself unavailable with a reason. A missing optional
//! backend must not fail the build of the parts that do work — the local
//! runtime and the whole decision path are useful without it.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=swift/vzrunner.swift");
    println!("cargo:rerun-if-changed=build.rs");

    // In a build script this is the *target* OS; `cfg!` would be the host.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let src = PathBuf::from("swift/vzrunner.swift");
    if !src.exists() {
        return;
    }

    let swiftc_ok = Command::new("swiftc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !swiftc_ok {
        println!(
            "cargo:warning=swiftc not found; the Virtualization.framework runtime will be unavailable"
        );
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let bin = out_dir.join("vzrunner");

    // `-swift-version 5` deliberately: the helper drives a Cocoa framework
    // across a dispatch queue, which Swift 6's strict concurrency checking
    // rejects without a lot of annotation that would not make it any safer.
    let status = Command::new("swiftc")
        .args(["-swift-version", "5", "-O", "-framework", "Virtualization", "-o"])
        .arg(&bin)
        .arg(&src)
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            println!("cargo:warning=swiftc failed ({s}); the VM runtime will be unavailable");
            return;
        }
        Err(e) => {
            println!(
                "cargo:warning=could not run swiftc ({e}); the VM runtime will be unavailable"
            );
            return;
        }
    }

    // Creating a VZVirtualMachine requires `com.apple.security.virtualization`.
    // Ad-hoc signing grants it for local use; a distributed build needs a real
    // Developer ID certificate, and the runtime reports the failure at
    // `availability()` rather than at the first VM creation.
    let plist = out_dir.join("vz-entitlements.plist");
    let _ = std::fs::write(
        &plist,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.virtualization</key><true/>
</dict></plist>
"#,
    );

    let signed = Command::new("codesign")
        .arg("--entitlements")
        .arg(&plist)
        .args(["-f", "-s", "-"])
        .arg(&bin)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !signed {
        println!(
            "cargo:warning=could not sign vzrunner with the virtualization entitlement; VM creation will fail"
        );
    }

    println!("cargo:rustc-env=SHELLGUARD_VZRUNNER={}", bin.display());
}
