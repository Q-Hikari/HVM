use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ENV");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    register_vendor_changes(Path::new("vendor/unicorn"));

    let mut config = cmake::Config::new("vendor/unicorn");
    if target_env() == "msvc" {
        config.define(
            "CMAKE_MSVC_RUNTIME_LIBRARY",
            "MultiThreaded$<$<CONFIG:Debug>:Debug>",
        );
    }
    let dst = config
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("UNICORN_LEGACY_STATIC_ARCHIVE", "ON")
        .define("UNICORN_ARCH", "x86")
        .define("UNICORN_BUILD_TESTS", "OFF")
        .define("UNICORN_INSTALL", "OFF")
        .build_target("unicorn_archive")
        .build();

    let archive = candidate_unicorn_archive(&dst).unwrap_or_else(|| {
        panic!(
            "bundled Unicorn static archive not found under {}",
            dst.display()
        )
    });
    let lib_dir = archive.parent().unwrap_or_else(|| {
        panic!(
            "bundled Unicorn archive has no parent directory: {}",
            archive.display()
        )
    });
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=unicorn");
    emit_system_link_libs();
}

fn emit_system_link_libs() {
    if target_env() != "msvc" && target_os() != "android" {
        println!("cargo:rustc-link-lib=pthread");
    }
    if target_os() != "windows" {
        println!("cargo:rustc-link-lib=m");
    }
}

fn candidate_unicorn_archive(root: &Path) -> Option<PathBuf> {
    let file_names: &[&str] = if target_os() == "windows" {
        &["unicorn.lib", "libunicorn.a"]
    } else {
        &["libunicorn.a"]
    };
    find_file_recursive(root, file_names)
}

fn target_env() -> String {
    std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default()
}

fn target_os() -> String {
    std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default()
}

fn find_file_recursive(root: &Path, file_names: &[&str]) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_file_recursive(&path, file_names) {
                return Some(found);
            }
            continue;
        }
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| file_names.iter().any(|candidate| candidate == &name))
            .unwrap_or(false)
        {
            return Some(path);
        }
    }
    None
}

fn register_vendor_changes(root: &Path) {
    if !root.exists() {
        return;
    }
    visit_dir(root);
}

fn visit_dir(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();
        if entry_path.is_dir() {
            visit_dir(&entry_path);
        } else {
            println!("cargo:rerun-if-changed={}", entry_path.display());
        }
    }
}
