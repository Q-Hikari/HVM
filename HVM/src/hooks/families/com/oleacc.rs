use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stdcall_definitions;

const EXPORTS: &[(&str, usize)] = &[
    ("AccessibleObjectFromWindow", 4),
    ("CreateStdAccessibleObject", 4),
    ("LresultFromObject", 3),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct OleaccHookLibrary;

impl HookLibrary for OleaccHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stdcall_definitions("oleacc.dll", EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_oleacc_hooks(registry: &mut HookRegistry) {
    registry.register_library(&OleaccHookLibrary);
}
