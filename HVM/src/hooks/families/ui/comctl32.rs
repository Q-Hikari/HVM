use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stdcall_definitions;

const EXPORTS: &[(&str, usize)] = &[("InitCommonControlsEx", 1)];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct Comctl32HookLibrary;

impl HookLibrary for Comctl32HookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stdcall_definitions("comctl32.dll", EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_comctl32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Comctl32HookLibrary);
}
