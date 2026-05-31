use hvm::hooks::register_all_family_hooks;
use hvm::hooks::registry::HookRegistry;

#[test]
fn synthetic_export_binding_returns_stable_stub_address() {
    let mut registry = HookRegistry::for_tests();
    let first = registry.bind_stub("kernel32.dll", "GetCurrentThreadId");
    let second = registry.bind_stub("kernel32.dll", "GetCurrentThreadId");

    assert_eq!(first, second);
}

#[test]
fn register_all_family_hooks_promotes_stubbed_exports_to_full_signatures() {
    let mut registry = HookRegistry::for_tests();
    register_all_family_hooks(&mut registry);

    let winhttp_open = registry
        .signature("winhttp.dll", "WinHttpOpen")
        .expect("winhttp signature should be registered");
    assert_eq!(winhttp_open.argc(), 5);

    let wsa_startup = registry
        .signature("ws2_32.dll", "WSAStartup")
        .expect("ws2_32 signature should be registered");
    assert_eq!(wsa_startup.argc(), 2);

    let shell_get_folder = registry
        .signature("shell32.dll", "SHGetFolderPathW")
        .expect("shell32 signature should be registered");
    assert_eq!(shell_get_folder.argc(), 5);
}

#[test]
fn api_set_contracts_inherit_host_param_specs_for_core_manual_families() {
    let mut registry = HookRegistry::for_tests();
    register_all_family_hooks(&mut registry);

    let load_library = registry
        .signature("api-ms-win-core-libraryloader", "LoadLibraryW")
        .expect("libraryloader contract signature should be registered");
    assert_eq!(load_library.argc(), 1);

    let open_process_token = registry
        .signature("api-ms-win-core-processthreads", "OpenProcessToken")
        .expect("processthreads contract signature should be registered");
    assert_eq!(open_process_token.argc(), 3);

    let co_initialize = registry
        .signature("api-ms-win-core-com", "CoInitializeEx")
        .expect("com contract signature should be registered");
    assert_eq!(co_initialize.argc(), 2);

    let enum_modules = registry
        .signature("api-ms-win-core-psapi", "K32EnumProcessModules")
        .expect("psapi contract signature should be registered");
    assert_eq!(enum_modules.argc(), 4);

    let version_info = registry
        .signature("api-ms-win-core-versionansi", "GetFileVersionInfoExA")
        .expect("versionansi contract signature should be registered");
    assert_eq!(version_info.argc(), 5);
}
