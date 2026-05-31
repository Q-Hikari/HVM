//! HVM Environment Collector
//!
//! Runs on a real Windows machine to collect system information and produce
//! an `environment_profile.json` that can be used directly by the HVM engine.
//!
//! Usage:
//!   hvm-collector.exe [output_path]
//!   hvm-collector.exe                  # outputs to environment_profile.json
//!   hvm-collector.exe profile.json     # outputs to profile.json

use serde::Serialize;
use std::env;
use std::fs;
use std::path::PathBuf;

mod profile;
mod collect;

use profile::EnvironmentProfile;

fn main() {
    let output_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "environment_profile.json".to_string());

    eprintln!("[hvm-collector] Collecting system information...");

    let profile = collect::collect_all();

    let json = serde_json::to_string_pretty(&profile).expect("failed to serialize profile");
    fs::write(&output_path, json).expect("failed to write output file");

    eprintln!(
        "[hvm-collector] Profile written to {} ({} bytes)",
        output_path,
        fs::metadata(&output_path)
            .map(|m| m.len())
            .unwrap_or(0)
    );

    // Print summary.
    eprintln!("[hvm-collector] Summary:");
    eprintln!("  OS: {} (build {})", profile.os_version.product_name, profile.os_version.build);
    eprintln!("  Computer: {}", profile.machine.computer_name);
    eprintln!("  User: {}", profile.machine.user_name);
    eprintln!("  Registry keys: {}", profile.registry.keys.len());
    eprintln!("  Services: {}", profile.services.len());
    eprintln!("  Processes: {}", profile.processes.len());
    eprintln!("  Users: {}", profile.users.len());
    eprintln!("  Network adapters: {}", profile.network.adapters.len());
    eprintln!("  Environment variables: {}", profile.environment_variables.len());
    eprintln!("  System32 files: {}", profile.system32_files.len());
}
