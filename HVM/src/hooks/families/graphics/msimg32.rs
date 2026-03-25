use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stdcall_definitions;

const EXPORTS: &[(&str, usize)] = &[("AlphaBlend", 11), ("TransparentBlt", 11)];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct Msimg32HookLibrary;

impl HookLibrary for Msimg32HookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stdcall_definitions("msimg32.dll", EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_msimg32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Msimg32HookLibrary);
}
