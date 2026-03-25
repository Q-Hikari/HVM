use crate::hooks::base::{CallConv, HookDefinition, HookLibrary};
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stdcall_definitions;

mod exports;

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct User32HookLibrary;

impl HookLibrary for User32HookLibrary {
    fn collect(&self) -> Vec<HookDefinition> {
        let mut definitions = stdcall_definitions("user32.dll", exports::STDCALL_EXPORTS);
        definitions.extend(
            exports::CDECL_EXPORTS
                .iter()
                .map(|(function, argc)| HookDefinition {
                    module: "user32.dll",
                    function,
                    argc: *argc,
                    call_conv: CallConv::Cdecl,
                }),
        );
        definitions
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_user32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&User32HookLibrary);
}
