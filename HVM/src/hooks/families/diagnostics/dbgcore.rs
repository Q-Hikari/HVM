use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "dbgcore.dll",
        "MiniDumpWriteDump",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbgcore.dll",
        "MiniDumpReadDumpStream",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct DbgcoreHookLibrary;

impl HookLibrary for DbgcoreHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_dbgcore_hooks(registry: &mut HookRegistry) {
    registry.register_library(&DbgcoreHookLibrary);
}
