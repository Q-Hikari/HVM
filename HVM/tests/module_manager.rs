use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::arch::{ArchSpec, X64_ARCH, X86_ARCH};
use hvm::config::EngineConfig;
use hvm::hooks::families::core::kernel32::register_kernel32_hooks;
use hvm::hooks::families::core::ntdll::register_ntdll_hooks;
use hvm::hooks::register_all_family_hooks;
use hvm::hooks::registry::HookRegistry;
use hvm::managers::module_manager::ModuleManager;
use hvm::models::{ForwardedExportTarget, ModuleRecord};
use hvm::samples::first_runnable_sample;

fn test_config() -> EngineConfig {
    EngineConfig::for_tests(PathBuf::from(".hvm_hikari_virtual_engine/output"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn real_snapshot_config_for_arch(arch: &'static ArchSpec) -> EngineConfig {
    let mut config = test_config();
    let snapshot_root = repo_root().join("system_dll");
    let arch_snapshot = if arch.is_x64() {
        snapshot_root.join("System32")
    } else {
        snapshot_root.join("SysWOW64")
    };
    config.module_search_paths = vec![arch_snapshot.clone(), snapshot_root];
    if arch.is_x64() {
        config.module_directory_x64 = Some(arch_snapshot);
    } else {
        config.module_directory_x86 = Some(arch_snapshot);
    }
    config
}

fn wtpsvc_sample_config() -> EngineConfig {
    let mut config = real_snapshot_config_for_arch(&X64_ARCH);
    config
        .module_search_paths
        .insert(0, repo_root().join("Sample").join("WtpSvc"));
    config.whitelist_modules = ["wtpsvc.exe", "wtplib.dll"]
        .into_iter()
        .map(str::to_string)
        .collect();
    config
}

fn test_module(name: &str, base: u64, synthetic: bool) -> ModuleRecord {
    ModuleRecord {
        name: name.to_string(),
        path: None,
        arch: "x86".to_string(),
        is_dll: name.to_ascii_lowercase().ends_with(".dll"),
        allow_execution: true,
        base,
        visible_base: base,
        size: 0x4000,
        entrypoint: base + 0x1000,
        image_base: base,
        time_date_stamp: 0,
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

fn read_u32(memory: &hvm::memory::manager::MemoryManager, address: u64) -> u32 {
    u32::from_le_bytes(memory.read(address, 4).unwrap().try_into().unwrap())
}

fn read_u16(memory: &hvm::memory::manager::MemoryManager, address: u64) -> u16 {
    u16::from_le_bytes(memory.read(address, 2).unwrap().try_into().unwrap())
}

fn read_c_string(memory: &hvm::memory::manager::MemoryManager, address: u64) -> String {
    let mut bytes = Vec::new();
    let mut cursor = address;
    loop {
        let byte = memory.read(cursor, 1).unwrap()[0];
        if byte == 0 {
            break;
        }
        bytes.push(byte);
        cursor += 1;
    }
    String::from_utf8(bytes).unwrap()
}

fn sample_export_hash(name: &str) -> u32 {
    let mut hash = 0x1020_3040u32;
    for mut byte in name.bytes() {
        if byte.is_ascii_uppercase() {
            byte.make_ascii_lowercase();
        }
        hash = hash
            .wrapping_mul(0x1_003f)
            .wrapping_add(u32::from(byte) ^ 0x1020_3040);
    }
    hash
}

fn resolve_export_by_sample_hash(
    manager: &ModuleManager,
    module: &ModuleRecord,
    export_hash: u32,
) -> Option<u64> {
    let memory = manager.memory();
    let pe_offset = u64::from(read_u32(memory, module.base + 0x3C));
    let nt_headers = module.base + pe_offset;
    let export_directory_rva = u64::from(read_u32(memory, nt_headers + 0x88));
    if export_directory_rva == 0 {
        return None;
    }

    let export_directory = module.base + export_directory_rva;
    let named_count = read_u32(memory, export_directory + 0x18) as usize;
    if named_count == 0 {
        return None;
    }

    let functions_rva = u64::from(read_u32(memory, export_directory + 0x1C));
    let names_rva = u64::from(read_u32(memory, export_directory + 0x20));
    let ordinals_rva = u64::from(read_u32(memory, export_directory + 0x24));

    for index in (0..named_count).rev() {
        let name_rva = u64::from(read_u32(
            memory,
            module.base + names_rva + (index * 4) as u64,
        ));
        let name = read_c_string(memory, module.base + name_rva);
        if sample_export_hash(&name) != export_hash {
            continue;
        }
        let ordinal_index = u64::from(read_u16(
            memory,
            module.base + ordinals_rva + (index * 2) as u64,
        ));
        let function_rva = u64::from(read_u32(
            memory,
            module.base + functions_rva + ordinal_index * 4,
        ));
        return Some(module.base + function_rva);
    }

    None
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
fn observed_api_set_families_canonicalize_to_expected_hosts() {
    let config = test_config();
    let mut hooks = HookRegistry::for_tests();
    let mut manager = ModuleManager::for_tests();

    let expectations = [
        ("api-ms-win-eventing-consumer-l1-1-1.dll", "sechost.dll"),
        ("api-ms-win-service-core-l1-1-2.dll", "sechost.dll"),
        ("api-ms-win-security-base-l1-2-0.dll", "kernelbase.dll"),
        ("api-ms-win-security-audit-l1-1-1.dll", "advapi32.dll"),
        ("api-ms-win-gdi-internal-uap-l1-1-0.dll", "gdi32.dll"),
        ("api-ms-win-shell-shellcom-l1-1-0.dll", "shell32.dll"),
        (
            "api-ms-win-stateseparation-helpers-l1-1-0.dll",
            "kernelbase.dll",
        ),
    ];

    for (requested, expected_host) in expectations {
        let module = manager
            .load_runtime_dependency(requested, &config, &mut hooks)
            .unwrap();
        assert_eq!(module.name, expected_host, "request {requested}");
        assert_eq!(
            manager.get_loaded(requested).unwrap().base,
            manager.get_loaded(expected_host).unwrap().base,
            "alias lookup for {requested}",
        );
    }
}

#[test]
fn api_set_contracts_reuse_real_snapshot_hosts_for_both_architectures() {
    let expectations = [
        ("api-ms-win-security-base-l1-2-0.dll", "kernelbase.dll"),
        ("api-ms-win-eventing-consumer-l1-1-1.dll", "sechost.dll"),
        ("api-ms-win-security-audit-l1-1-1.dll", "advapi32.dll"),
        ("api-ms-win-gdi-internal-uap-l1-1-0.dll", "gdi32.dll"),
        ("api-ms-win-shell-shellcom-l1-1-0.dll", "shell32.dll"),
    ];

    for arch in [&X86_ARCH, &X64_ARCH] {
        let config = real_snapshot_config_for_arch(arch);
        let mut hooks = HookRegistry::for_tests();
        let mut manager = ModuleManager::for_arch(arch);

        for (requested, expected_host) in expectations {
            let module = manager
                .load_runtime_dependency(requested, &config, &mut hooks)
                .unwrap();
            let loaded = manager.get_loaded(requested).unwrap();
            assert_eq!(module.name.to_ascii_lowercase(), expected_host);
            assert_eq!(loaded.name.to_ascii_lowercase(), expected_host);
            assert!(
                !loaded.synthetic,
                "{requested} should map to a real host on {}",
                arch.name
            );
            assert_eq!(
                loaded
                    .path
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_ascii_lowercase(),
                expected_host,
            );
            assert_eq!(
                manager.get_loaded(expected_host).unwrap().base,
                loaded.base,
                "alias lookup for {requested} on {}",
                arch.name,
            );
        }
    }
}

#[test]
fn real_snapshot_exports_prefer_real_addresses_before_synthetic_fallback() {
    let expectations = [
        (
            "api-ms-win-security-base-l1-2-0.dll",
            "kernelbase.dll",
            "GetAppContainerAce",
        ),
        (
            "api-ms-win-eventing-consumer-l1-1-1.dll",
            "sechost.dll",
            "QueryTraceProcessingHandle",
        ),
        (
            "api-ms-win-shell-shellcom-l1-1-0.dll",
            "shell32.dll",
            "SHCoCreateInstance",
        ),
    ];

    for arch in [&X86_ARCH, &X64_ARCH] {
        let config = real_snapshot_config_for_arch(arch);
        let mut hooks = HookRegistry::for_tests();
        let mut manager = ModuleManager::for_arch(arch);

        for (requested, expected_host, function) in expectations {
            let module = manager
                .load_runtime_dependency(requested, &config, &mut hooks)
                .unwrap();
            let resolved =
                manager.resolve_export(module.base, &config, &mut hooks, Some(function), None);
            let normalized_function = function.to_ascii_lowercase();

            assert_ne!(
                resolved, 0,
                "{requested}!{function} should resolve on {}",
                arch.name
            );
            let owner = manager
                .get_by_address(resolved)
                .expect("resolved export should point into a loaded real host image");
            assert_eq!(owner.name.to_ascii_lowercase(), expected_host);
            assert!(
                !owner.synthetic,
                "{requested}!{function} should stay on a real host"
            );

            let binding = hooks
                .binding_for_address(resolved)
                .expect("real export should remain bound for runtime interception");
            assert_eq!(binding.0, expected_host);
            assert_eq!(binding.1, normalized_function);
            assert!(
                hooks.signature_for_address(resolved).is_none(),
                "test expects no explicit hook signature for {requested}!{function}",
            );
        }
    }
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
fn synthetic_ntdll_module_materializes_registered_memory_exports() {
    let config = test_config();
    let mut hooks = HookRegistry::for_tests();
    register_ntdll_hooks(&mut hooks);
    let mut manager = ModuleManager::for_tests();

    let module = manager
        .load_runtime_dependency("ntdll.dll", &config, &mut hooks)
        .unwrap();
    let has_fill = manager
        .get_loaded("ntdll.dll")
        .unwrap()
        .exports_by_name
        .contains_key("rtlfillmemory");
    let has_move = manager
        .get_loaded("ntdll.dll")
        .unwrap()
        .exports_by_name
        .contains_key("rtlmovememory");
    let rtl_fill = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("RtlFillMemory"),
        None,
    );
    let rtl_move = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("RtlMoveMemory"),
        None,
    );

    assert!(has_fill);
    assert!(has_move);
    assert_ne!(rtl_fill, 0);
    assert_ne!(rtl_move, 0);
    assert_eq!(manager.get_by_address(rtl_move).unwrap().base, module.base);
}

#[test]
fn synthetic_ntdll_module_materializes_loader_and_runtime_exports() {
    let config = test_config();
    let mut hooks = HookRegistry::for_tests();
    register_ntdll_hooks(&mut hooks);
    let mut manager = ModuleManager::for_tests();

    let module = manager
        .load_runtime_dependency("ntdll.dll", &config, &mut hooks)
        .unwrap();
    let ldr_load_dll =
        manager.resolve_export(module.base, &config, &mut hooks, Some("LdrLoadDll"), None);
    let ldr_get_procedure_address = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("LdrGetProcedureAddress"),
        None,
    );
    let rtl_random_ex =
        manager.resolve_export(module.base, &config, &mut hooks, Some("RtlRandomEx"), None);
    let rtl_acquire_peb_lock = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("RtlAcquirePebLock"),
        None,
    );
    let rtl_release_peb_lock = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("RtlReleasePebLock"),
        None,
    );
    let rtl_free_unicode_string = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("RtlFreeUnicodeString"),
        None,
    );
    let rtl_int64_to_unicode_string = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("RtlInt64ToUnicodeString"),
        None,
    );
    let rtl_integer_to_char = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("RtlIntegerToChar"),
        None,
    );
    let ki_user_exception_dispatcher = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("KiUserExceptionDispatcher"),
        None,
    );
    let nt_get_tick_count = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("NtGetTickCount"),
        None,
    );

    assert_ne!(ldr_load_dll, 0);
    assert_ne!(ldr_get_procedure_address, 0);
    assert_ne!(rtl_random_ex, 0);
    assert_ne!(rtl_acquire_peb_lock, 0);
    assert_ne!(rtl_release_peb_lock, 0);
    assert_ne!(rtl_free_unicode_string, 0);
    assert_ne!(rtl_int64_to_unicode_string, 0);
    assert_ne!(rtl_integer_to_char, 0);
    assert_ne!(ki_user_exception_dispatcher, 0);
    assert_ne!(nt_get_tick_count, 0);
    assert_eq!(
        manager.get_by_address(ldr_load_dll).unwrap().base,
        module.base
    );
    assert_eq!(
        manager
            .get_by_address(ldr_get_procedure_address)
            .unwrap()
            .base,
        module.base
    );
    let ki_stub = manager
        .memory()
        .read(ki_user_exception_dispatcher, 16)
        .unwrap();

    assert_eq!(
        ki_stub,
        vec![0x48, 0x8B, 0x05, 0x01, 0x00, 0x00, 0x00, 0xC3, 0, 0, 0, 0, 0, 0, 0, 0,]
    );
}

#[test]
fn synthetic_eventing_api_set_modules_materialize_registered_exports() {
    let config = test_config();
    let mut hooks = HookRegistry::for_tests();
    register_all_family_hooks(&mut hooks);
    let mut manager = ModuleManager::for_tests();

    let controller = manager
        .load_runtime_dependency(
            "api-ms-win-eventing-controller-l1-1-0.dll",
            &config,
            &mut hooks,
        )
        .unwrap();
    let consumer = manager
        .load_runtime_dependency(
            "api-ms-win-eventing-consumer-l1-1-0.dll",
            &config,
            &mut hooks,
        )
        .unwrap();

    let start_trace = manager.resolve_export(
        controller.base,
        &config,
        &mut hooks,
        Some("StartTraceW"),
        None,
    );
    let close_trace =
        manager.resolve_export(consumer.base, &config, &mut hooks, Some("CloseTrace"), None);

    assert_ne!(start_trace, 0);
    assert_ne!(close_trace, 0);
    assert_eq!(
        manager.get_by_address(start_trace).unwrap().base,
        controller.base
    );
    assert_eq!(
        manager.get_by_address(close_trace).unwrap().base,
        consumer.base
    );
}

#[test]
fn synthetic_eventing_hosts_reuse_contract_hook_definitions() {
    let config = test_config();
    let mut hooks = HookRegistry::for_tests();
    register_all_family_hooks(&mut hooks);
    let mut manager = ModuleManager::for_tests();

    let module = manager
        .load_runtime_dependency(
            "api-ms-win-eventing-consumer-l1-1-1.dll",
            &config,
            &mut hooks,
        )
        .unwrap();
    let open_trace =
        manager.resolve_export(module.base, &config, &mut hooks, Some("OpenTraceW"), None);
    let close_trace =
        manager.resolve_export(module.base, &config, &mut hooks, Some("CloseTrace"), None);
    let query_trace = manager.resolve_export(
        module.base,
        &config,
        &mut hooks,
        Some("QueryTraceProcessingHandle"),
        None,
    );

    assert_eq!(module.name, "sechost.dll");
    assert_ne!(open_trace, 0);
    assert_ne!(close_trace, 0);
    assert_ne!(query_trace, 0);
    assert_eq!(
        manager.get_by_address(open_trace).unwrap().base,
        module.base
    );
    assert_eq!(
        manager.get_by_address(close_trace).unwrap().base,
        module.base
    );
}

#[test]
fn synthetic_x64_cabinet_module_matches_sample_export_hash_resolver() {
    let config = test_config();
    let mut hooks = HookRegistry::for_tests();
    register_all_family_hooks(&mut hooks);
    let mut manager = ModuleManager::for_arch(&X64_ARCH);

    let module = manager
        .load_runtime_dependency("cabinet.dll", &config, &mut hooks)
        .unwrap();

    let create =
        resolve_export_by_sample_hash(&manager, &module, sample_export_hash("CreateDecompressor"));
    let decompress =
        resolve_export_by_sample_hash(&manager, &module, sample_export_hash("Decompress"));
    let close =
        resolve_export_by_sample_hash(&manager, &module, sample_export_hash("CloseDecompressor"));

    assert_eq!(
        create,
        manager
            .get_loaded("cabinet.dll")
            .and_then(|loaded| loaded.exports_by_name.get("createdecompressor").copied())
    );
    assert_eq!(
        decompress,
        manager
            .get_loaded("cabinet.dll")
            .and_then(|loaded| loaded.exports_by_name.get("decompress").copied())
    );
    assert_eq!(
        close,
        manager
            .get_loaded("cabinet.dll")
            .and_then(|loaded| loaded.exports_by_name.get("closedecompressor").copied())
    );
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

    assert!(matches!(error, hvm::error::VmError::ModuleNotFound(_)));
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
fn whitelisted_wtplib_exports_stay_observed_after_wtpsvc_import_resolution() {
    let config = wtpsvc_sample_config();
    let mut hooks = HookRegistry::for_tests();
    register_all_family_hooks(&mut hooks);
    let mut manager = ModuleManager::for_arch(&X64_ARCH);

    let main = manager
        .load_runtime_dependency("WtpSvc.exe", &config, &mut hooks)
        .unwrap();
    assert_eq!(main.name, "WtpSvc.exe");

    let wtplib = manager
        .get_loaded("wtplib.dll")
        .expect("wtplib should be loaded");
    assert!(
        wtplib.allow_execution,
        "whitelisted DLL should stay executable"
    );

    for (name, address) in [
        ("WtpEnableFilter", 0x1800_37C90u64),
        ("WtpOpenDevice", 0x1800_62BE0u64),
        ("sqlite3_win32_is_nt", 0x1800_36180u64),
    ] {
        assert!(
            hooks.bound_lookup(address).is_none(),
            "{name} unexpectedly became hook-dispatchable at 0x{address:X}"
        );
        let observed = hooks
            .observed_real_export_for_address(address)
            .unwrap_or_else(|| panic!("{name} should remain observable at 0x{address:X}"));
        assert_eq!(observed.0, "wtplib.dll");
    }
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
