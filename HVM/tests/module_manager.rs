use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::EngineConfig;
use hvm::hooks::families::core::kernel32::register_kernel32_hooks;
use hvm::hooks::registry::HookRegistry;
use hvm::managers::module_manager::ModuleManager;
use hvm::models::{ForwardedExportTarget, ModuleRecord};
use hvm::samples::first_runnable_sample;

fn test_config() -> EngineConfig {
    EngineConfig::for_tests(PathBuf::from(".hvm_hikari_virtual_engine/output"))
}

fn test_module(name: &str, base: u64, synthetic: bool) -> ModuleRecord {
    ModuleRecord {
        name: name.to_string(),
        path: None,
        arch: "x86".to_string(),
        is_dll: name.to_ascii_lowercase().ends_with(".dll"),
        base,
        size: 0x4000,
        entrypoint: base + 0x1000,
        image_base: base,
        synthetic,
        tls_callbacks: Vec::new(),
        initialized: true,
        exports_by_name: Default::default(),
        export_name_text_by_key: Default::default(),
        exports_by_ordinal: Default::default(),
        forwarded_exports_by_name: Default::default(),
        forwarded_exports_by_ordinal: Default::default(),
        stub_cursor: 0x1000,
    }
}

#[test]
fn main_module_load_populates_exports_and_entrypoint() {
    let sample = first_runnable_sample()
        .unwrap()
        .expect("expected at least one runnable x86 sample");
    let mut manager = ModuleManager::for_tests();
    let module = manager.load_real_module(sample.path).unwrap();

    assert!(module.entrypoint > module.base);
    assert!(module.size > 0);
    assert_eq!(module.arch, "x86");
    assert!(manager.memory().is_range_mapped(module.base, module.size));
}

#[test]
fn api_set_dependency_requests_canonicalize_to_host_module() {
    let config = test_config();
    let mut hooks = HookRegistry::for_tests();
    let mut manager = ModuleManager::for_tests();

    let module = manager
        .load_runtime_dependency("api-ms-win-core-file-l1-2-0", &config, &mut hooks)
        .unwrap();

    assert_eq!(module.name, "kernel32.dll");
    assert_eq!(
        manager.get_loaded("kernel32.dll").unwrap().base,
        manager
            .get_loaded("api-ms-win-core-file-l1-2-0.dll")
            .unwrap()
            .base
    );
}

#[test]
fn resolve_export_follows_forwarders_by_name_and_ordinal() {
    let config = test_config();
    let mut hooks = HookRegistry::for_tests();
    let mut manager = ModuleManager::for_tests();

    let mut target = test_module("kernel32.dll", 0x7600_0000, false);
    target
        .exports_by_name
        .insert("sleep".to_string(), 0x7600_1200);
    target.exports_by_ordinal.insert(7, 0x7600_1300);
    manager.insert_module_record_for_test(target);

    let mut forwarder = test_module("forwarder.dll", 0x7700_0000, false);
    forwarder.forwarded_exports_by_name.insert(
        "sleep".to_string(),
        ForwardedExportTarget::ByName {
            module: "kernel32".to_string(),
            function: "sleep".to_string(),
        },
    );
    forwarder.forwarded_exports_by_ordinal.insert(
        5,
        ForwardedExportTarget::ByOrdinal {
            module: "kernel32.dll".to_string(),
            ordinal: 7,
        },
    );
    let forwarder_base = forwarder.base;
    manager.insert_module_record_for_test(forwarder);

    assert_eq!(
        manager.resolve_export(forwarder_base, &config, &mut hooks, Some("Sleep"), None),
        0x7600_1200
    );
    assert_eq!(
        manager.resolve_export(forwarder_base, &config, &mut hooks, None, Some(5)),
        0x7600_1300
    );
}

#[test]
fn synthetic_module_headers_keep_scan_sensitive_fields_small() {
    let config = test_config();
    let mut hooks = HookRegistry::for_tests();
    let mut manager = ModuleManager::for_tests();

    let module = manager
        .load_runtime_dependency("ntdll.dll", &config, &mut hooks)
        .unwrap();

    let coff_tail = manager.memory().read(module.base + 0x94, 4).unwrap();
    let image_base = manager.memory().read(module.base + 0xB4, 4).unwrap();
    let reported_size_of_image = manager.memory().read(module.base + 0xD0, 4).unwrap();
    let dll_characteristics = manager.memory().read(module.base + 0xDE, 2).unwrap();
    let export_name_rva = manager.memory().read(module.base + 0x100C, 4).unwrap();
    let export_name_count = manager.memory().read(module.base + 0x1018, 4).unwrap();
    let edata_name = manager.memory().read(module.base + 0x178, 4).unwrap();
    let text_name = manager.memory().read(module.base + 0x1A0, 4).unwrap();
    let text_fill = manager.memory().read(module.base + 0x8000, 4).unwrap();
    let edata_characteristics = manager.memory().read(module.base + 0x19C, 4).unwrap();
    let text_characteristics = manager.memory().read(module.base + 0x1C4, 4).unwrap();
    let coff_tail = u32::from_le_bytes(coff_tail.try_into().unwrap());
    let reported_size_of_image = u32::from_le_bytes(reported_size_of_image.try_into().unwrap());
    let expected_size_of_image = (module
        .stub_cursor
        .max(0xA000)
        .max(0x9000)
        .saturating_add(0x0FFF)
        & !0x0FFF) as u32;

    assert_eq!(coff_tail & 0xFFFF, 0xE0);
    assert_eq!(coff_tail >> 16, 0x2102);
    assert_eq!(
        u32::from_le_bytes(image_base.try_into().unwrap()),
        module.image_base as u32
    );
    assert_eq!(reported_size_of_image, expected_size_of_image);
    assert_eq!(
        u16::from_le_bytes(dll_characteristics.try_into().unwrap()),
        0x0140
    );
    assert_ne!(u32::from_le_bytes(export_name_rva.try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(export_name_count.try_into().unwrap()), 0);
    assert_eq!(edata_name.as_slice(), b".eda");
    assert_eq!(text_name.as_slice(), b".tex");
    assert_eq!(u32::from_le_bytes(text_fill.try_into().unwrap()), 0);
    assert_eq!(
        u32::from_le_bytes(edata_characteristics.try_into().unwrap()),
        0x4000_0040
    );
    assert_eq!(
        u32::from_le_bytes(text_characteristics.try_into().unwrap()),
        0x6000_0020
    );
}

#[test]
fn synthetic_runtime_modules_materialize_registered_hook_exports() {
    let config = test_config();
    let mut hooks = HookRegistry::for_tests();
    register_kernel32_hooks(&mut hooks);
    let mut manager = ModuleManager::for_tests();

    let module = manager
        .load_runtime_dependency("kernel32.dll", &config, &mut hooks)
        .unwrap();
    let get_command_line = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("GetCommandLineW"),
        None,
    );
    let get_proc_address = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("GetProcAddress"),
        None,
    );
    let export_name_rva = manager.memory().read(module.base + 0x160C, 4).unwrap();
    let export_name_count = manager.memory().read(module.base + 0x1618, 4).unwrap();

    assert_ne!(get_command_line, 0);
    assert_ne!(get_proc_address, 0);
    assert_eq!(
        manager.get_by_address(get_command_line).unwrap().base,
        module.base
    );
    assert_eq!(
        manager.get_by_address(get_proc_address).unwrap().base,
        module.base
    );
    assert_ne!(u32::from_le_bytes(export_name_rva.try_into().unwrap()), 0);
    assert!(u32::from_le_bytes(export_name_count.try_into().unwrap()) > 0);
}

#[test]
fn runtime_dependency_prefers_real_module_when_snapshot_exists_in_search_paths() {
    let sample = first_runnable_sample()
        .unwrap()
        .expect("expected at least one runnable x86 sample");
    let mut config = test_config();
    config.module_search_paths = vec![sample.path.parent().unwrap().to_path_buf()];
    let mut hooks = HookRegistry::for_tests();
    let mut manager = ModuleManager::for_tests();

    let module = manager
        .load_runtime_dependency(
            sample.path.file_name().unwrap().to_string_lossy().as_ref(),
            &config,
            &mut hooks,
        )
        .unwrap();

    assert!(!module.synthetic);
    assert_eq!(module.path.as_ref(), Some(&sample.path));
}

#[test]
fn runtime_dependency_finds_real_module_inside_snapshot_root_with_case_insensitive_lookup() {
    let sample = first_runnable_sample()
        .unwrap()
        .expect("expected at least one runnable x86 sample");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-module-snapshot-{}-{timestamp}",
        std::process::id()
    ));
    let snapshot_dir = root.join("dlls").join("System32");
    fs::create_dir_all(&snapshot_dir).unwrap();
    let snapshot_path = snapshot_dir.join(sample.name.to_ascii_uppercase());
    fs::copy(&sample.path, &snapshot_path).unwrap();

    let mut config = test_config();
    config.module_search_paths = vec![root.clone()];
    let mut hooks = HookRegistry::for_tests();
    let mut manager = ModuleManager::for_tests();

    let module = manager
        .load_runtime_dependency(&sample.name.to_ascii_lowercase(), &config, &mut hooks)
        .unwrap();

    assert!(!module.synthetic);
    assert_eq!(module.path.as_ref(), Some(&snapshot_path));

    fs::remove_file(snapshot_path).unwrap();
    fs::remove_dir(snapshot_dir).unwrap();
    fs::remove_dir(root.join("dlls")).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn runtime_dependency_respects_modules_always_exist_disable() {
    let mut config = test_config();
    config.modules_always_exist = false;
    let mut hooks = HookRegistry::for_tests();
    let mut manager = ModuleManager::for_tests();

    let error = manager
        .load_runtime_dependency("totally-missing-module.dll", &config, &mut hooks)
        .unwrap_err();

    assert!(matches!(
        error,
        hvm::error::VmError::ModuleNotFound(_)
    ));
}

#[test]
fn runtime_dependency_uses_arch_decoy_directory_before_synthetic_fallback() {
    let sample = first_runnable_sample()
        .unwrap()
        .expect("expected at least one runnable x86 sample");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-module-decoy-{}-{timestamp}",
        std::process::id()
    ));
    let decoy_dir = root.join("decoys").join("x86");
    fs::create_dir_all(&decoy_dir).unwrap();
    let decoy_path = decoy_dir.join(sample.name.to_ascii_uppercase());
    fs::copy(&sample.path, &decoy_path).unwrap();

    let mut config = test_config();
    config.module_directory_x86 = Some(decoy_dir.clone());
    let mut hooks = HookRegistry::for_tests();
    let mut manager = ModuleManager::for_tests();

    let module = manager
        .load_runtime_dependency(&sample.name, &config, &mut hooks)
        .unwrap();

    assert!(!module.synthetic);
    assert_eq!(module.path.as_ref(), Some(&decoy_path));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn functions_always_exist_binds_missing_exports_for_real_modules() {
    let mut config = test_config();
    config.functions_always_exist = true;
    let mut hooks = HookRegistry::for_tests();
    let mut manager = ModuleManager::for_tests();

    let module = test_module("custom.dll", 0x7800_0000, false);
    let module_base = module.base;
    manager.insert_module_record_for_test(module);

    let stub = manager.resolve_export(module_base, &config, &mut hooks, Some("MissingProc"), None);

    assert_ne!(stub, 0);
    assert_eq!(
        hooks.binding_for_address(stub),
        Some(("custom.dll", "missingproc"))
    );
    assert!(manager.get_by_address(stub).is_none());
}
