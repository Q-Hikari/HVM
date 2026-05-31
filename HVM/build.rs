use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ENV");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");

    let vendor_dir = Path::new("vendor/unicorn");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let stamp_file = out_dir.join("unicorn-build-stamp.txt");
    let link_cache = out_dir.join("unicorn-link-dir.txt");

    let current_hash = hash_vendor_dir(vendor_dir);
    let prev_hash = fs::read_to_string(&stamp_file).unwrap_or_default();

    let lib_dir = if current_hash == prev_hash {
        // Source unchanged — reuse previously built archive.
        let cached = fs::read_to_string(&link_cache).unwrap_or_default();
        if cached.is_empty() {
            panic!(
                "unicorn link cache is empty; delete {} to force a full rebuild",
                link_cache.display()
            );
        }
        PathBuf::from(cached)
    } else {
        let dst = build_unicorn(vendor_dir);
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
        let _ = fs::write(&stamp_file, &current_hash);
        let _ = fs::write(&link_cache, lib_dir.to_string_lossy().as_ref());
        lib_dir.to_path_buf()
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=unicorn");
    emit_system_link_libs();
}

fn build_unicorn(vendor_dir: &Path) -> PathBuf {
    let mut config = cmake::Config::new(vendor_dir);
    config
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("UNICORN_LEGACY_STATIC_ARCHIVE", "ON")
        .define("UNICORN_ARCH", "x86")
        .define("UNICORN_BUILD_TESTS", "OFF")
        .define("UNICORN_INSTALL", "OFF")
        .build_target("unicorn_archive")
        .build()
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

/// Hashes all files under `root` to detect source changes.
/// Only emits `rerun-if-changed` for the top-level CMakeLists.txt so that
/// Cargo doesn't walk the entire tree on every invocation.
fn hash_vendor_dir(root: &Path) -> String {
    if !root.exists() {
        return String::new();
    }
    // Track the top-level CMakeLists.txt for Cargo change detection.
    let cmake_lists = root.join("CMakeLists.txt");
    if cmake_lists.exists() {
        println!("cargo:rerun-if-changed={}", cmake_lists.display());
    }
    let mut hasher = DefaultHasher::new();
    hash_dir(root, &mut hasher);
    format!("{:016x}", hasher.finish())
}

fn hash_dir(path: &Path, hasher: &mut DefaultHasher) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    let mut sorted: Vec<_> = entries.flatten().collect();
    sorted.sort_by_key(|e| e.file_name());
    for entry in sorted {
        let entry_path = entry.path();
        if entry_path.is_dir() {
            hash_dir(&entry_path, hasher);
        } else if let Ok(contents) = fs::read(&entry_path) {
            entry_path.to_string_lossy().hash(hasher);
            contents.hash(hasher);
        }
    }
}
