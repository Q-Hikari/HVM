use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

const EXPORTS: &[(&str, LogicalAbi)] = &[
    ("CreateDXGIFactory", LogicalAbi::WinApi),
    ("CreateDXGIFactory1", LogicalAbi::WinApi),
    ("CreateDXGIFactory2", LogicalAbi::WinApi),
    // Synthetic vtable method stubs (not real exports).
    ("__vm_dxgi_factory_EnumAdapters", LogicalAbi::WinApi),
    (
        "__vm_dxgi_factory_MakeWindowAssociation",
        LogicalAbi::WinApi,
    ),
    ("__vm_dxgi_factory_Stub", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_dxgi_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("dxgi.dll", &EXPORTS);
}

#[cfg(test)]
mod tests {
    use super::register_dxgi_hooks;
    use crate::hooks::registry::HookRegistry;

    #[test]
    fn registers_dxgi_factory_creation_exports() {
        let mut registry = HookRegistry::for_tests();
        register_dxgi_hooks(&mut registry);

        for function in [
            "CreateDXGIFactory",
            "CreateDXGIFactory1",
            "CreateDXGIFactory2",
        ] {
            assert!(
                registry.has_signature_for("dxgi.dll", function),
                "missing dxgi registration for {function}"
            );
        }
    }
}
