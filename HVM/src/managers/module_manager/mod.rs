use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use goblin::pe::PE;

use crate::api_set::{canonical_runtime_module_name, contract_hook_family};
use crate::arch::{ArchSpec, X86_ARCH};
use crate::config::EngineConfig;
use crate::error::{MemoryError, VmError};
use crate::hooks::registry::{
    initialize_synthetic_module_image, synthetic_module_reserve_size, HookRegistry,
    SYNTHETIC_STUB_RVA_START, SYNTHETIC_TEXT_RVA,
};
use crate::memory::manager::{align_up, MemoryManager, PAGE_SIZE};
use crate::models::{ForwardedExportTarget, ModuleRecord};
use crate::pe::imports::collect_import_bindings;
use crate::pe::loader::map_image;
use crate::pe::relocations::apply_delta_relocations;

const MAX_FORWARD_EXPORT_DEPTH: usize = 8;
const SNAPSHOT_SEARCH_SUFFIXES: &[&str] = &[
    "",
    "System32",
    "SysWOW64",
    "Windows",
    "Windows/System32",
    "Windows/SysWOW64",
    "dlls",
    "dlls/System32",
    "dlls/SysWOW64",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedExportBinding {
    requested_module: String,
    requested_function: String,
    resolved_module: String,
    resolved_function: String,
    resolved_address: u64,
}

/// Owns loaded module records and the memory manager that backs them.
#[derive(Debug)]
pub struct ModuleManager {
    arch: &'static ArchSpec,
    memory: MemoryManager,
    loaded_by_name: HashMap<String, ModuleRecord>,
    alias_by_name: HashMap<String, String>,
    loaded_by_base: HashMap<u64, String>,
    loaded_by_visible_base: HashMap<u64, String>,
    load_order: Vec<String>,
    /// Sorted by base address for O(log n) address-to-module lookup.
    base_index: Vec<(u64, String)>,
}

mod load_ops;
mod queries;

fn normalize_module_name(path: &Path) -> String {
    // On Linux, backslashes are not path separators.  Normalise Windows
    // paths (e.g. "F:\a\..\b.dll") so file_name() correctly extracts
    // just the final component.
    let normalized_path: String = path.to_string_lossy().replace('\\', "/");
    let normalized = Path::new(&normalized_path);
    let file_name = normalized
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    if file_name.contains('.') {
        file_name
    } else if file_name.is_empty() {
        file_name
    } else {
        format!("{file_name}.dll")
    }
}

fn should_canonicalize_runtime_request(name_or_path: &str) -> bool {
    !name_or_path.contains('/') && !name_or_path.contains('\\') && !name_or_path.contains(':')
}

fn resolve_module_path(name_or_path: &str, search_paths: &[PathBuf]) -> Result<PathBuf, VmError> {
    let raw_path = Path::new(name_or_path);
    if raw_path.exists() {
        return std::path::absolute(raw_path).map_err(|source| VmError::ReadFile {
            path: raw_path.to_path_buf(),
            source,
        });
    }
    if raw_path.is_absolute() {
        return Err(VmError::ModuleNotFound(name_or_path.to_string()));
    }

    let candidate_names = if raw_path.extension().is_some() {
        vec![raw_path.to_path_buf()]
    } else {
        vec![raw_path.to_path_buf(), raw_path.with_extension("dll")]
    };

    for root in search_paths {
        for search_root in module_snapshot_search_roots(root) {
            for candidate_name in &candidate_names {
                if let Some(candidate) =
                    resolve_case_insensitive_relative(&search_root, candidate_name)
                {
                    return std::path::absolute(&candidate).map_err(|source| VmError::ReadFile {
                        path: candidate.clone(),
                        source,
                    });
                }
            }
        }
    }

    Err(VmError::ModuleNotFound(name_or_path.to_string()))
}

fn module_snapshot_search_roots(root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for suffix in SNAPSHOT_SEARCH_SUFFIXES {
        let candidate = if suffix.is_empty() {
            root.to_path_buf()
        } else {
            root.join(suffix)
        };
        if !roots.iter().any(|existing| existing == &candidate) {
            roots.push(candidate);
        }
    }
    roots
}

fn resolve_case_insensitive_relative(base: &Path, relative: &Path) -> Option<PathBuf> {
    let mut current = base.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return None;
        };
        let exact = current.join(name);
        if exact.exists() {
            current = exact;
            continue;
        }
        let needle = name.to_string_lossy().to_ascii_lowercase();
        let matched = fs::read_dir(&current)
            .ok()?
            .filter_map(Result::ok)
            .find(|entry| entry.file_name().to_string_lossy().to_ascii_lowercase() == needle)?;
        current = matched.path();
    }
    current.exists().then_some(current)
}

#[cfg(test)]
mod tests {
    use super::ModuleManager;
    use crate::config::EngineConfig;
    use crate::hooks::families::core::api_set_contracts::register_api_set_contract_hooks;
    use crate::hooks::families::core::kernel32::register_kernel32_hooks;
    use crate::hooks::registry::{
        synthetic_module_reserve_size, HookRegistry, SYNTHETIC_STUB_RVA_START,
    };
    use crate::memory::manager::{PROT_EXEC, PROT_READ, PROT_WRITE};
    use crate::models::{ForwardedExportTarget, ModuleRecord};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn strip_execute_from_image_clears_exec_bits_for_image_regions() {
        let mut manager = ModuleManager::for_tests();
        manager
            .memory_mut()
            .map_region(0x1000, 0x1000, PROT_READ | PROT_EXEC, "image.text")
            .unwrap();
        manager
            .memory_mut()
            .map_region(0x2000, 0x1000, PROT_READ | PROT_EXEC, "image.rdata")
            .unwrap();
        manager
            .memory_mut()
            .map_region(0x3000, 0x1000, PROT_READ | PROT_EXEC, "outside")
            .unwrap();

        manager.strip_execute_from_image(0x1000, 0x2000);

        let text = manager
            .memory()
            .regions
            .values()
            .find(|region| region.base == 0x1000)
            .expect("image.text region should exist");
        let rdata = manager
            .memory()
            .regions
            .values()
            .find(|region| region.base == 0x2000)
            .expect("image.rdata region should exist");
        let outside = manager
            .memory()
            .regions
            .values()
            .find(|region| region.base == 0x3000)
            .expect("outside region should exist");

        assert_eq!(text.perms & PROT_EXEC, 0);
        assert_eq!(rdata.perms & PROT_EXEC, 0);
        assert_ne!(outside.perms & PROT_EXEC, 0);
    }

    #[test]
    fn forwarded_exports_preserve_runtime_hook_definitions() {
        let mut manager = ModuleManager::for_tests();
        let mut hooks = HookRegistry::for_tests();
        register_kernel32_hooks(&mut hooks);
        let config = EngineConfig::for_tests(PathBuf::from("/tmp"));

        manager.insert_module_record_for_test(ModuleRecord {
            name: "kernel32.dll".to_string(),
            path: None,
            arch: manager.arch().name.to_string(),
            is_dll: true,
            allow_execution: false,
            base: 0x5000,
            visible_base: 0x5000,
            size: 0x1000,
            entrypoint: 0,
            image_base: 0x5000,
            time_date_stamp: 0,
            synthetic: false,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: BTreeMap::from([("createfilemappingw".to_string(), 0x5100)]),
            export_name_text_by_key: BTreeMap::from([(
                "createfilemappingw".to_string(),
                "CreateFileMappingW".to_string(),
            )]),
            exports_by_ordinal: BTreeMap::new(),
            forwarded_exports_by_name: BTreeMap::new(),
            forwarded_exports_by_ordinal: BTreeMap::new(),
            stub_cursor: 0,
        });

        manager.insert_module_record_for_test(ModuleRecord {
            name: "api-ms-win-core-memory-l1-1-0.dll".to_string(),
            path: None,
            arch: manager.arch().name.to_string(),
            is_dll: true,
            allow_execution: false,
            base: 0x7000,
            visible_base: 0x7000,
            size: 0x1000,
            entrypoint: 0,
            image_base: 0x7000,
            time_date_stamp: 0,
            synthetic: false,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: BTreeMap::new(),
            export_name_text_by_key: BTreeMap::new(),
            exports_by_ordinal: BTreeMap::new(),
            forwarded_exports_by_name: BTreeMap::from([(
                "createfilemappingw".to_string(),
                ForwardedExportTarget::ByName {
                    module: "kernel32.dll".to_string(),
                    function: "createfilemappingw".to_string(),
                },
            )]),
            forwarded_exports_by_ordinal: BTreeMap::new(),
            stub_cursor: 0,
        });

        let binding = manager
            .resolve_export_binding_with_depth(
                0x7000,
                "api-ms-win-core-memory-l1-1-0.dll",
                "CreateFileMappingW",
                &config,
                &mut hooks,
                Some("CreateFileMappingW"),
                None,
                0,
            )
            .expect("forwarded export should resolve");
        let resolved = binding.resolved_address;

        assert_eq!(resolved, 0x5100);
        assert_eq!(
            binding.requested_module,
            "api-ms-win-core-memory-l1-1-0.dll"
        );
        assert_eq!(binding.requested_function, "CreateFileMappingW");
        assert_eq!(binding.resolved_module, "kernel32.dll");
        assert_eq!(binding.resolved_function, "CreateFileMappingW");
        let bound = hooks
            .bound_lookup(0x5100)
            .expect("forwarded target should bind the real export address");
        assert_eq!(bound.module, "kernel32.dll");
        assert_eq!(bound.function, "CreateFileMappingW");
        assert!(
            bound.signature.is_some(),
            "forwarded kernel32 export should still resolve to the registered hook"
        );
    }

    #[test]
    fn resolve_export_returns_visible_address_and_binds_both_variants() {
        let mut manager = ModuleManager::for_tests();
        let mut hooks = HookRegistry::for_tests();
        register_kernel32_hooks(&mut hooks);
        let config = EngineConfig::for_tests(PathBuf::from("/tmp"));

        manager.insert_module_record_for_test(ModuleRecord {
            name: "kernel32.dll".to_string(),
            path: None,
            arch: manager.arch().name.to_string(),
            is_dll: true,
            allow_execution: false,
            base: 0x7601_0000,
            visible_base: 0x6B80_0000,
            size: 0x0200_0000,
            entrypoint: 0,
            image_base: 0x6B80_0000,
            time_date_stamp: 0,
            synthetic: false,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: BTreeMap::from([("createmutexa".to_string(), 0x7612_1610)]),
            export_name_text_by_key: BTreeMap::from([(
                "createmutexa".to_string(),
                "CreateMutexA".to_string(),
            )]),
            exports_by_ordinal: BTreeMap::new(),
            forwarded_exports_by_name: BTreeMap::new(),
            forwarded_exports_by_ordinal: BTreeMap::new(),
            stub_cursor: 0,
        });

        let resolved =
            manager.resolve_export(0x6B80_0000, &config, &mut hooks, Some("CreateMutexA"), None);

        assert_eq!(resolved, 0x6B91_1610);

        let mapped = hooks
            .bound_lookup(0x7612_1610)
            .expect("mapped export address should remain hook-bound");
        assert_eq!(mapped.module, "kernel32.dll");
        assert_eq!(mapped.function, "CreateMutexA");

        let visible = hooks
            .bound_lookup(0x6B91_1610)
            .expect("visible export alias should also be hook-bound");
        assert_eq!(visible.module, "kernel32.dll");
        assert_eq!(visible.function, "CreateMutexA");
    }

    #[test]
    fn resolve_export_for_executable_module_observes_without_hook_binding() {
        let mut manager = ModuleManager::for_tests();
        let mut hooks = HookRegistry::for_tests();
        let config = EngineConfig::for_tests(PathBuf::from("/tmp"));

        manager.insert_module_record_for_test(ModuleRecord {
            name: "sample.dll".to_string(),
            path: None,
            arch: manager.arch().name.to_string(),
            is_dll: true,
            allow_execution: true,
            base: 0x1800_0000,
            visible_base: 0x6B80_0000,
            size: 0x0200_0000,
            entrypoint: 0,
            image_base: 0x1800_0000,
            time_date_stamp: 0,
            synthetic: false,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: BTreeMap::from([("runme".to_string(), 0x1800_1010)]),
            export_name_text_by_key: BTreeMap::from([("runme".to_string(), "RunMe".to_string())]),
            exports_by_ordinal: BTreeMap::new(),
            forwarded_exports_by_name: BTreeMap::new(),
            forwarded_exports_by_ordinal: BTreeMap::new(),
            stub_cursor: 0,
        });

        let resolved =
            manager.resolve_export(0x6B80_0000, &config, &mut hooks, Some("RunMe"), None);

        assert_eq!(resolved, 0x6B80_1010);
        assert!(
            hooks.bound_lookup(0x6B80_1010).is_none(),
            "allow_execution exports must not become hook-dispatchable"
        );
        let observed = hooks
            .observed_real_export_for_address(0x6B80_1010)
            .expect("allow_execution export should still be observable");
        assert_eq!(observed.0, "sample.dll");
        assert_eq!(observed.1, "runme");
    }

    #[test]
    fn synthetic_api_set_exports_remain_hook_dispatchable() {
        let mut manager = ModuleManager::for_tests();
        let mut hooks = HookRegistry::for_tests();
        register_api_set_contract_hooks(&mut hooks);
        register_kernel32_hooks(&mut hooks);
        let config = EngineConfig::for_tests(PathBuf::from("/tmp"));

        let module = manager
            .load_runtime_dependency("api-ms-win-core-fibers-l1-1-1.dll", &config, &mut hooks)
            .expect("api-set contract should load synthetically");
        assert!(module.synthetic, "api-set fibers contract should be synthetic");

        let resolved = manager.resolve_export(
            module.visible_base,
            &config,
            &mut hooks,
            Some("FlsGetValue"),
            None,
        );

        assert_ne!(resolved, 0, "synthetic export should resolve");
        let bound = hooks
            .bound_lookup(resolved)
            .expect("synthetic api-set export should stay hook-dispatchable");
        assert_eq!(bound.module, "api-ms-win-core-fibers-l1-1-1.dll");
        assert_eq!(bound.function, "FlsGetValue");
        assert!(
            bound.signature.is_some(),
            "synthetic api-set export should resolve into the fibers hook signature"
        );
        assert!(
            hooks.observed_real_export_for_address(resolved).is_none(),
            "synthetic api-set export must not be downgraded into an observed-only real export"
        );
    }

    #[test]
    fn visible_alias_mirrors_later_mapped_writes() {
        let mut manager = ModuleManager::for_tests();
        let base = 0x5000u64;
        manager
            .memory_mut()
            .map_region(base, 0x3000, PROT_READ | PROT_WRITE, "test.dll")
            .unwrap();
        manager.memory_mut().write(base + 0x100, b"ABCD").unwrap();
        manager.insert_module_record_for_test(ModuleRecord {
            name: "test.dll".to_string(),
            path: None,
            arch: manager.arch().name.to_string(),
            is_dll: true,
            allow_execution: false,
            base,
            visible_base: base,
            size: 0x3000,
            entrypoint: 0,
            image_base: base,
            time_date_stamp: 0,
            synthetic: false,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: BTreeMap::new(),
            export_name_text_by_key: BTreeMap::new(),
            exports_by_ordinal: BTreeMap::new(),
            forwarded_exports_by_name: BTreeMap::new(),
            forwarded_exports_by_ordinal: BTreeMap::new(),
            stub_cursor: 0,
        });

        assert!(manager.set_visible_base(base, 0x15000));
        manager.memory_mut().write(base + 0x100, b"WXYZ").unwrap();
        manager
            .mirror_write_into_visible_alias(base + 0x100, b"WXYZ")
            .unwrap();

        assert_eq!(manager.memory().read(0x15100, 4).unwrap(), b"WXYZ");
    }

    #[test]
    fn synthetic_export_population_updates_visible_alias_image() {
        let mut manager = ModuleManager::for_tests();
        let mut hooks = HookRegistry::for_tests();
        register_kernel32_hooks(&mut hooks);

        let anticipated_exports = hooks.functions_for_module("kernel32.dll").len();
        let module = manager
            .load_synthetic_module("kernel32.dll", anticipated_exports)
            .expect("synthetic kernel32 should load");
        assert!(manager.set_visible_base(module.base, 0x6B80_0000));

        manager
            .populate_synthetic_module_exports(module.base, &mut hooks)
            .expect("visible alias should track export refresh");

        assert_eq!(
            manager
                .memory()
                .read(module.base + SYNTHETIC_STUB_RVA_START, 1)
                .unwrap(),
            vec![0xC3]
        );
        assert_eq!(
            manager
                .memory()
                .read(0x6B80_0000 + SYNTHETIC_STUB_RVA_START, 1)
                .unwrap(),
            vec![0xC3]
        );
    }

    #[test]
    fn synthetic_modules_reserve_compact_space_for_known_exports() {
        let mut manager = ModuleManager::for_tests();
        let mut hooks = HookRegistry::for_tests();
        register_kernel32_hooks(&mut hooks);

        let anticipated_exports = hooks.functions_for_module("kernel32.dll").len();
        let module = manager
            .load_synthetic_module("kernel32.dll", anticipated_exports)
            .expect("synthetic kernel32 should load");

        assert_eq!(
            module.size,
            synthetic_module_reserve_size(anticipated_exports)
        );
        assert!(module.size < 0x400000);

        manager
            .populate_synthetic_module_exports(module.base, &mut hooks)
            .expect("known kernel32 exports should populate");

        let loaded = manager
            .get_loaded("kernel32.dll")
            .expect("loaded kernel32 synthetic module should exist");
        assert!(
            loaded.stub_cursor <= loaded.size,
            "populated stubs must stay within the reserved synthetic image"
        );
    }

    /// Test A (design doc §11.1): Name query returns exactly one canonical guest_address,
    /// regardless of alias registration order.
    #[test]
    fn name_query_returns_unique_canonical_guest_address() {
        let mut manager = ModuleManager::for_tests();
        let mut hooks = HookRegistry::for_tests();
        register_kernel32_hooks(&mut hooks);
        let config = EngineConfig::for_tests(PathBuf::from("/tmp"));

        // Simulate a real DLL with different base/visible_base (the A0044620 scenario)
        manager.insert_module_record_for_test(ModuleRecord {
            name: "kernel32.dll".to_string(),
            path: None,
            arch: manager.arch().name.to_string(),
            is_dll: true,
            allow_execution: false,
            base: 0x6B80_0000,         // internal mapped base
            visible_base: 0x76A2_0000, // guest-visible base
            size: 0x0200_0000,
            entrypoint: 0,
            image_base: 0x6B80_0000,
            time_date_stamp: 0,
            synthetic: false,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: BTreeMap::from([
                ("closehandle".to_string(), 0x6B91_1610),
                ("createfilemappinga".to_string(), 0x6B91_2000),
            ]),
            export_name_text_by_key: BTreeMap::from([
                ("closehandle".to_string(), "CloseHandle".to_string()),
                (
                    "createfilemappinga".to_string(),
                    "CreateFileMappingA".to_string(),
                ),
            ]),
            exports_by_ordinal: BTreeMap::new(),
            forwarded_exports_by_name: BTreeMap::new(),
            forwarded_exports_by_ordinal: BTreeMap::new(),
            stub_cursor: 0,
        });

        // Bind all exports — this must produce canonical guest addresses
        manager.bind_all_real_exports("kernel32.dll", &mut hooks);

        // binding_address must return the visible_base variant, not the mapped base
        let close_handle_canonical = hooks
            .binding_address("kernel32.dll", "CloseHandle")
            .expect("CloseHandle should have a canonical address");
        assert_eq!(
            close_handle_canonical, 0x76B3_1610,
            "canonical should be visible_base (0x76A2...) + RVA, not mapped base (0x6B80...)"
        );

        // Resolve via GetProcAddress path — must return the same canonical address
        let resolved_close = manager.resolve_export(
            0x76A2_0000, // guest queries by visible_base
            &config,
            &mut hooks,
            Some("CloseHandle"),
            None,
        );
        assert_eq!(
            resolved_close, close_handle_canonical,
            "GetProcAddress must return the same canonical address"
        );

        let resolved_cfm = manager.resolve_export(
            0x76A2_0000,
            &config,
            &mut hooks,
            Some("CreateFileMappingA"),
            None,
        );
        assert_eq!(resolved_cfm, 0x76B3_2000);
    }

    /// Test B (design doc §11.1): Both backing and guest addresses hit the same hook.
    #[test]
    fn dual_address_variants_dispatch_to_same_hook() {
        let mut manager = ModuleManager::for_tests();
        let mut hooks = HookRegistry::for_tests();
        register_kernel32_hooks(&mut hooks);
        let config = EngineConfig::for_tests(PathBuf::from("/tmp"));

        let mapped_base = 0x6B80_0000u64;
        let visible_base = 0x76A2_0000u64;
        let mapped_addr = 0x6B91_1610u64; // CloseHandle in mapped space
        let visible_addr = 0x76B3_1610u64; // CloseHandle in visible space

        manager.insert_module_record_for_test(ModuleRecord {
            name: "kernel32.dll".to_string(),
            path: None,
            arch: manager.arch().name.to_string(),
            is_dll: true,
            allow_execution: false,
            base: mapped_base,
            visible_base,
            size: 0x0200_0000,
            entrypoint: 0,
            image_base: mapped_base,
            time_date_stamp: 0,
            synthetic: false,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: BTreeMap::from([("closehandle".to_string(), mapped_addr)]),
            export_name_text_by_key: BTreeMap::from([(
                "closehandle".to_string(),
                "CloseHandle".to_string(),
            )]),
            exports_by_ordinal: BTreeMap::new(),
            forwarded_exports_by_name: BTreeMap::new(),
            forwarded_exports_by_ordinal: BTreeMap::new(),
            stub_cursor: 0,
        });

        // Resolve via GetProcAddress — triggers canonical+alias binding
        let resolved =
            manager.resolve_export(visible_base, &config, &mut hooks, Some("CloseHandle"), None);
        assert_eq!(
            resolved, visible_addr,
            "GetProcAddress must return guest address"
        );

        // Both mapped and visible addresses must dispatch to the same hook
        let mapped_bound = hooks
            .bound_lookup(mapped_addr)
            .expect("mapped address must dispatch");
        let visible_bound = hooks
            .bound_lookup(visible_addr)
            .expect("visible address must dispatch");
        assert_eq!(mapped_bound.module, "kernel32.dll");
        assert_eq!(visible_bound.module, "kernel32.dll");
        assert_eq!(mapped_bound.function, "CloseHandle");
        assert_eq!(visible_bound.function, "CloseHandle");
        assert!(
            mapped_bound.signature.is_some(),
            "mapped alias should resolve the registered hook signature"
        );
        assert!(
            visible_bound.signature.is_some(),
            "visible canonical should resolve the registered hook signature"
        );
    }

    /// Test C (design doc §11.1): GetProcAddress returns guest address when visible_base != base.
    #[test]
    fn getprocaddress_returns_guest_address_not_mapped_address() {
        let mut manager = ModuleManager::for_tests();
        let mut hooks = HookRegistry::for_tests();
        register_kernel32_hooks(&mut hooks);
        let config = EngineConfig::for_tests(PathBuf::from("/tmp"));

        let mapped_base = 0x6B80_0000u64;
        let visible_base = 0x76A2_0000u64;

        manager.insert_module_record_for_test(ModuleRecord {
            name: "kernel32.dll".to_string(),
            path: None,
            arch: manager.arch().name.to_string(),
            is_dll: true,
            allow_execution: false,
            base: mapped_base,
            visible_base,
            size: 0x0200_0000,
            entrypoint: 0,
            image_base: mapped_base,
            time_date_stamp: 0,
            synthetic: false,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: BTreeMap::from([
                ("closehandle".to_string(), mapped_base + 0x11_610),
                ("createfilemappinga".to_string(), mapped_base + 0x12_000),
            ]),
            export_name_text_by_key: BTreeMap::from([
                ("closehandle".to_string(), "CloseHandle".to_string()),
                (
                    "createfilemappinga".to_string(),
                    "CreateFileMappingA".to_string(),
                ),
            ]),
            exports_by_ordinal: BTreeMap::new(),
            forwarded_exports_by_name: BTreeMap::new(),
            forwarded_exports_by_ordinal: BTreeMap::new(),
            stub_cursor: 0,
        });

        // Resolve by visible_base — the typical sample path
        let close_handle =
            manager.resolve_export(visible_base, &config, &mut hooks, Some("CloseHandle"), None);
        let create_file_mapping = manager.resolve_export(
            visible_base,
            &config,
            &mut hooks,
            Some("CreateFileMappingA"),
            None,
        );

        // Must be in visible_base coordinate space
        assert!(
            close_handle >= visible_base && close_handle < visible_base + 0x0200_0000,
            "CloseHandle address 0x{close_handle:X} must be in visible range [0x{visible_base:X}, 0x{:X})",
            visible_base + 0x0200_0000
        );
        assert!(
            create_file_mapping >= visible_base && create_file_mapping < visible_base + 0x0200_0000,
            "CreateFileMappingA address 0x{create_file_mapping:X} must be in visible range"
        );

        // Must NOT be in mapped_base coordinate space
        assert!(
            !(close_handle >= mapped_base && close_handle < mapped_base + 0x0200_0000),
            "CloseHandle must NOT return mapped-base address"
        );
        assert!(
            !(create_file_mapping >= mapped_base
                && create_file_mapping < mapped_base + 0x0200_0000),
            "CreateFileMappingA must NOT return mapped-base address"
        );
    }

    /// Test D (A0044620 fix): forwarded export from kernel32 to kernelbase
    /// must return the kernelbase canonical address and bind both canonical
    /// and alias variants.  The hook dispatcher must be able to dispatch at
    /// the forwarded target's address.
    #[test]
    fn forwarded_export_to_kernelbase_binds_and_dispatches() {
        let mut manager = ModuleManager::for_tests();
        let mut hooks = HookRegistry::for_tests();
        register_kernel32_hooks(&mut hooks);
        let config = EngineConfig::for_tests(PathBuf::from("/tmp"));

        // kernel32.dll mapped at 0x6B800000 with visible_base at 0x6B800000
        // (no override).  CloseHandle is forwarded to kernelbase.dll.
        manager.insert_module_record_for_test(ModuleRecord {
            name: "kernel32.dll".to_string(),
            path: None,
            arch: manager.arch().name.to_string(),
            is_dll: true,
            allow_execution: false,
            base: 0x6B80_0000,
            visible_base: 0x6B80_0000,
            size: 0x0200_0000,
            entrypoint: 0,
            image_base: 0x6B80_0000,
            time_date_stamp: 0,
            synthetic: false,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: BTreeMap::new(), // no direct export
            export_name_text_by_key: BTreeMap::new(),
            exports_by_ordinal: BTreeMap::new(),
            forwarded_exports_by_name: BTreeMap::from([(
                "closehandle".to_string(),
                ForwardedExportTarget::ByName {
                    module: "kernelbase.dll".to_string(),
                    function: "closehandle".to_string(),
                },
            )]),
            forwarded_exports_by_ordinal: BTreeMap::new(),
            stub_cursor: 0,
        });

        // kernelbase.dll mapped at 0x76A20000 with visible_base at 0x76A20000
        // CloseHandle is a direct export here.
        manager.insert_module_record_for_test(ModuleRecord {
            name: "kernelbase.dll".to_string(),
            path: None,
            arch: manager.arch().name.to_string(),
            is_dll: true,
            allow_execution: false,
            base: 0x76A2_0000,
            visible_base: 0x76A2_0000,
            size: 0x0200_0000,
            entrypoint: 0,
            image_base: 0x76A2_0000,
            time_date_stamp: 0,
            synthetic: false,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: BTreeMap::from([("closehandle".to_string(), 0x76A3_3180)]),
            export_name_text_by_key: BTreeMap::from([(
                "closehandle".to_string(),
                "CloseHandle".to_string(),
            )]),
            exports_by_ordinal: BTreeMap::new(),
            forwarded_exports_by_name: BTreeMap::new(),
            forwarded_exports_by_ordinal: BTreeMap::new(),
            stub_cursor: 0,
        });

        // Resolve via GetProcAddress path: kernel32!CloseHandle → forward → kernelbase
        let resolved =
            manager.resolve_export(0x6B80_0000, &config, &mut hooks, Some("CloseHandle"), None);

        // The resolved address should be in kernelbase's space (0x76A...)
        // because that's where the forwarded function actually lives.
        assert_eq!(
            resolved, 0x76A3_3180,
            "forwarded export should return kernelbase canonical address"
        );

        // The address must be bound in the hook registry for dispatch.
        assert!(
            hooks.is_bound_address(0x76A3_3180),
            "kernelbase CloseHandle address must be bound for hook dispatch"
        );

        // Dispatch must find the hook signature via hook-space fallback.
        let bound = hooks
            .bound_lookup(0x76A3_3180)
            .expect("kernelbase address must dispatch to a hook");
        assert_eq!(bound.function, "CloseHandle");
        assert!(
            bound.signature.is_some(),
            "forwarded kernelbase export must resolve hook signature via hook space"
        );
    }

    /// Test E (A0044620 fix): when kernelbase has a visible_base different
    /// from its mapped base, forwarded exports must return the guest-visible
    /// canonical address, not the mapped address.
    #[test]
    fn forwarded_export_uses_target_visible_base_for_canonical() {
        let mut manager = ModuleManager::for_tests();
        let mut hooks = HookRegistry::for_tests();
        register_kernel32_hooks(&mut hooks);
        let config = EngineConfig::for_tests(PathBuf::from("/tmp"));

        // kernel32.dll mapped at 0x6B800000, visible_base = 0x6B800000
        manager.insert_module_record_for_test(ModuleRecord {
            name: "kernel32.dll".to_string(),
            path: None,
            arch: manager.arch().name.to_string(),
            is_dll: true,
            allow_execution: false,
            base: 0x6B80_0000,
            visible_base: 0x6B80_0000,
            size: 0x0200_0000,
            entrypoint: 0,
            image_base: 0x6B80_0000,
            time_date_stamp: 0,
            synthetic: false,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: BTreeMap::new(),
            export_name_text_by_key: BTreeMap::new(),
            exports_by_ordinal: BTreeMap::new(),
            forwarded_exports_by_name: BTreeMap::from([(
                "createmutexa".to_string(),
                ForwardedExportTarget::ByName {
                    module: "kernelbase.dll".to_string(),
                    function: "createmutexa".to_string(),
                },
            )]),
            forwarded_exports_by_ordinal: BTreeMap::new(),
            stub_cursor: 0,
        });

        // kernelbase.dll mapped at 0x76A20000, visible_base = 0x6B900000
        // CreateMutexA at mapped RVA 0x11610
        let kb_mapped_base = 0x76A2_0000u64;
        let kb_visible_base = 0x6B90_0000u64;
        let createmutex_mapped = kb_mapped_base + 0x1_1610; // 0x76A31610
        let createmutex_visible = kb_visible_base + 0x1_1610; // 0x6B911610

        manager.insert_module_record_for_test(ModuleRecord {
            name: "kernelbase.dll".to_string(),
            path: None,
            arch: manager.arch().name.to_string(),
            is_dll: true,
            allow_execution: false,
            base: kb_mapped_base,
            visible_base: kb_visible_base,
            size: 0x0200_0000,
            entrypoint: 0,
            image_base: kb_mapped_base,
            time_date_stamp: 0,
            synthetic: false,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: BTreeMap::from([("createmutexa".to_string(), createmutex_mapped)]),
            export_name_text_by_key: BTreeMap::from([(
                "createmutexa".to_string(),
                "CreateMutexA".to_string(),
            )]),
            exports_by_ordinal: BTreeMap::new(),
            forwarded_exports_by_name: BTreeMap::new(),
            forwarded_exports_by_ordinal: BTreeMap::new(),
            stub_cursor: 0,
        });

        // Resolve: kernel32 → forward → kernelbase
        let resolved =
            manager.resolve_export(0x6B80_0000, &config, &mut hooks, Some("CreateMutexA"), None);

        // Must return the guest-visible canonical address (0x6B9...), NOT
        // the mapped address (0x76A...).
        assert_eq!(
            resolved, createmutex_visible,
            "forwarded export must return guest-visible canonical address 0x{createmutex_visible:X}, got 0x{resolved:X}"
        );

        // Both mapped and visible addresses must dispatch.
        assert!(
            hooks.is_bound_address(createmutex_visible),
            "canonical visible address must be bound"
        );
        assert!(
            hooks.is_bound_address(createmutex_mapped),
            "mapped alias address must be bound for dispatch"
        );

        let visible_bound = hooks
            .bound_lookup(createmutex_visible)
            .expect("visible canonical must dispatch");
        assert_eq!(visible_bound.function, "CreateMutexA");
        assert!(
            visible_bound.signature.is_some(),
            "visible canonical must resolve hook signature"
        );

        let mapped_bound = hooks
            .bound_lookup(createmutex_mapped)
            .expect("mapped alias must dispatch");
        assert_eq!(mapped_bound.function, "CreateMutexA");
        assert!(
            mapped_bound.signature.is_some(),
            "mapped alias must resolve hook signature"
        );
    }
}
