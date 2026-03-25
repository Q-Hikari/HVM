use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stdcall_definitions;

const EXPORTS: &[(&str, usize)] = &[("OleUIBusyW", 1)];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct OledlgHookLibrary;

impl HookLibrary for OledlgHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stdcall_definitions("oledlg.dll", EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_oledlg_hooks(registry: &mut HookRegistry) {
    registry.register_library(&OledlgHookLibrary);
}
