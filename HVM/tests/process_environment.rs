use std::path::PathBuf;

use hvm::memory::manager::MemoryManager;
use hvm::models::ModuleRecord;
use hvm::runtime::windows_env::WindowsProcessEnvironment;

fn loader_test_module(name: &str, path: Option<&str>, base: u64) -> ModuleRecord {
    ModuleRecord {
        name: name.to_string(),
        path: path.map(PathBuf::from),
        arch: "x86".to_string(),
        is_dll: false,
        base,
        size: 0x5000,
        entrypoint: base + 0x1000,
        image_base: base,
        synthetic: path.is_none(),
        tls_callbacks: Vec::new(),
        initialized: true,
        exports_by_name: Default::default(),
        export_name_text_by_key: Default::default(),
        exports_by_ordinal: Default::default(),
        forwarded_exports_by_name: Default::default(),
        forwarded_exports_by_ordinal: Default::default(),
        stub_cursor: 0,
    }
}

#[test]
fn tls_alloc_updates_peb_bitmap_and_slot_storage() {
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    let slot = env.allocate_tls_slot().unwrap();

    env.set_tls_value(slot, 0x1234_5678).unwrap();

    assert_eq!(env.read_tls_value(slot).unwrap(), 0x1234_5678);
    assert!(env.is_tls_bit_set(slot).unwrap());
    assert_eq!(
        env.read_pointer(env.current_teb() + env.offsets().teb_tls_pointer as u64)
            .unwrap(),
        env.layout().tls_slots_base
    );
}

#[test]
fn tls_free_clears_peb_bitmap_and_slot_storage() {
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    let slot = env.allocate_tls_slot().unwrap();

    env.set_tls_value(slot, 0x1234_5678).unwrap();
    assert!(env.free_tls_slot(slot).unwrap());

    assert_eq!(env.read_tls_value(slot).unwrap(), 0);
    assert!(!env.is_tls_bit_set(slot).unwrap());
    assert!(!env.free_tls_slot(slot).unwrap());
}

#[test]
fn configure_process_parameters_writes_stable_command_line_buffer() {
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    env.configure_process_parameters("getmidm2.exe", r"C:\Sandbox\Sample")
        .unwrap();

    let first = env.layout().command_line_buffer;
    let second = env.layout().command_line_buffer;

    assert_eq!(first, second);
    assert_eq!(env.read_wide_string(first).unwrap(), "getmidm2.exe");
}

#[test]
fn configure_process_parameters_writes_python_style_environment_block() {
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    env.configure_process_parameters("getmidm2.exe", r"C:\Sandbox\Sample")
        .unwrap();

    let first = r"PATH=C:\Windows\System32";
    let second = r"TMP=.\hikari\output";
    let base = env.layout().environment_w_buffer;
    let second_base = base + ((first.encode_utf16().count() + 1) * 2) as u64;

    assert_eq!(env.read_wide_string(base).unwrap(), first);
    assert_eq!(env.read_wide_string(second_base).unwrap(), second);
}

#[test]
fn configure_process_parameters_can_write_runtime_specific_environment_block() {
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    let dll_path =
        r"C:\Windows\System32;G:\RustroverProjects\Vm_Eng_Scan\Sample;C:\Windows\SysWOW64";
    let environment = vec![
        ("PATH".to_string(), dll_path.to_string()),
        (
            "TMP".to_string(),
            r"G:\RustroverProjects\Vm_Eng_Scan\.hvm_hikari_virtual_engine\output".to_string(),
        ),
        (
            "APPDATA".to_string(),
            r"C:\Users\analyst\AppData\Roaming".to_string(),
        ),
    ];
    env.configure_process_parameters_with_runtime_details_and_environment(
        r"C:\Sandbox\host.exe",
        "host.exe -service",
        r"C:\Sandbox",
        dll_path,
        &environment,
    )
    .unwrap();

    let first = format!("PATH={dll_path}");
    let second = r"TMP=G:\RustroverProjects\Vm_Eng_Scan\.hvm_hikari_virtual_engine\output";
    let third = r"APPDATA=C:\Users\analyst\AppData\Roaming";
    let base = env.layout().environment_w_buffer;
    let second_base = base + ((first.encode_utf16().count() + 1) * 2) as u64;
    let third_base = second_base + ((second.encode_utf16().count() + 1) * 2) as u64;

    assert_eq!(env.read_wide_string(base).unwrap(), first);
    assert_eq!(env.read_wide_string(second_base).unwrap(), second);
    assert_eq!(env.read_wide_string(third_base).unwrap(), third);
}

#[test]
fn set_current_directory_updates_mirrored_buffer() {
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    env.configure_process_parameters("getmidm2.exe", r"C:\Sandbox\Sample")
        .unwrap();

    env.set_current_directory(r"C:\Sandbox\Drop").unwrap();

    assert_eq!(
        env.read_wide_string(env.layout().current_directory_buffer)
            .unwrap(),
        r"C:\Sandbox\Drop"
    );
}

#[test]
fn allocate_thread_teb_returns_distinct_thread_contexts() {
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    let first = env.allocate_thread_teb(0x7020_0000, 0x7000_0000).unwrap();
    let second = env.allocate_thread_teb(0x7040_0000, 0x7020_0000).unwrap();

    assert_ne!(first.teb_base, second.teb_base);
    assert_eq!(env.current_teb(), first.teb_base);
}

#[test]
fn sync_last_error_updates_current_thread_teb() {
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    let first = env.allocate_thread_teb(0x7020_0000, 0x7000_0000).unwrap();

    env.bind_current_thread(first.teb_base).unwrap();
    env.sync_last_error(0x1234);

    let raw = env
        .read_pointer(first.teb_base + env.offsets().teb_last_error as u64)
        .unwrap();
    assert_eq!(raw, 0x1234);
}

#[test]
fn configure_process_parameters_populates_peb_process_parameters_block() {
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    env.configure_process_parameters_with_image_path(
        r"C:\Sandbox\host.exe",
        r"host.exe -service",
        r"C:\Sandbox",
    )
    .unwrap();

    let process_parameters = env
        .read_pointer(env.current_peb() + env.offsets().peb_process_parameters as u64)
        .unwrap();
    let image_path_buffer = env
        .read_pointer(
            process_parameters + env.offsets().process_parameters_image_path_name as u64 + 4,
        )
        .unwrap();
    let command_line_buffer = env
        .read_pointer(process_parameters + env.offsets().process_parameters_command_line as u64 + 4)
        .unwrap();
    let current_directory_buffer = env
        .read_pointer(
            process_parameters + env.offsets().process_parameters_current_directory as u64 + 4,
        )
        .unwrap();
    let environment_buffer = env
        .read_pointer(process_parameters + env.offsets().process_parameters_environment as u64)
        .unwrap();

    assert_eq!(process_parameters, env.layout().process_parameters_base);
    assert_eq!(image_path_buffer, env.layout().image_path_buffer);
    assert_eq!(command_line_buffer, env.layout().command_line_buffer);
    assert_eq!(
        current_directory_buffer,
        env.layout().current_directory_buffer
    );
    assert_eq!(environment_buffer, env.layout().environment_w_buffer);
    assert_eq!(
        env.read_wide_string(image_path_buffer).unwrap(),
        r"C:\Sandbox\host.exe"
    );
    assert_eq!(
        env.read_wide_string(command_line_buffer).unwrap(),
        r"host.exe -service"
    );
    assert_eq!(
        env.read_wide_string(current_directory_buffer).unwrap(),
        r"C:\Sandbox"
    );
}

#[test]
fn sync_modules_populates_loader_module_lists_in_load_order() {
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    let modules = vec![
        loader_test_module("sample.exe", Some("/tmp/sample.exe"), 0x0040_0000),
        loader_test_module("kernel32.dll", None, 0x7600_0000),
        loader_test_module("user32.dll", None, 0x7700_0000),
    ];

    env.sync_modules(&modules).unwrap();

    assert_eq!(
        env.loader_module_bases().unwrap(),
        vec![0x0040_0000, 0x7600_0000, 0x7700_0000]
    );
    assert_eq!(
        env.loader_module_names().unwrap(),
        vec!["sample.exe", "kernel32.dll", "user32.dll"]
    );
}

#[test]
fn sync_modules_rebuilds_loader_lists_after_module_removal() {
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    let modules = vec![
        loader_test_module("sample.exe", Some("/tmp/sample.exe"), 0x0040_0000),
        loader_test_module("kernel32.dll", None, 0x7600_0000),
    ];
    env.sync_modules(&modules).unwrap();
    env.sync_modules(&modules[..1]).unwrap();

    assert_eq!(env.loader_module_bases().unwrap(), vec![0x0040_0000]);
    assert_eq!(env.loader_module_names().unwrap(), vec!["sample.exe"]);
}

#[test]
fn materialize_into_rematerializes_dirty_teb_page() {
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    let mut memory = MemoryManager::for_tests();

    env.materialize_into(&mut memory).unwrap();
    let initial_region_count = memory.regions.len();

    env.materialize_into(&mut memory).unwrap();
    assert_eq!(memory.regions.len(), initial_region_count);

    let teb_last_error = env.current_teb() + env.offsets().teb_last_error as u64;
    env.sync_last_error(0x1234_5678);
    env.materialize_into(&mut memory).unwrap();

    assert_eq!(memory.read_u32(teb_last_error).unwrap(), 0x1234_5678);
    assert_eq!(memory.regions.len(), initial_region_count);
}
