use hvm::hooks::registry::HookRegistry;

#[test]
fn synthetic_export_binding_returns_stable_stub_address() {
    let mut registry = HookRegistry::for_tests();
    let first = registry.bind_stub("kernel32.dll", "GetCurrentThreadId");
    let second = registry.bind_stub("kernel32.dll", "GetCurrentThreadId");

    assert_eq!(first, second);
}
