use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[(
    "mswsock.dll",
    "TransmitFile",
    7,
    crate::hooks::base::CallConv::Stdcall,
)];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct MswsockHookLibrary;

impl HookLibrary for MswsockHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_mswsock_hooks(registry: &mut HookRegistry) {
    registry.register_library(&MswsockHookLibrary);
}
