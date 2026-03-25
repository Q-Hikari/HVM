use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "dbghelp.dll",
        "SymInitialize",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "SymInitializeW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "SymCleanup",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "SymSetOptions",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "SymGetOptions",
        0,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "SymLoadModuleEx",
        8,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "SymLoadModuleExW",
        8,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "SymGetModuleBase64",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "SymFunctionTableAccess64",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "SymRefreshModuleList",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "SymFromAddr",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "SymFromAddrW",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "SymGetLineFromAddr64",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "UnDecorateSymbolName",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "MiniDumpWriteDump",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dbghelp.dll",
        "StackWalk64",
        9,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct DbghelpHookLibrary;

impl HookLibrary for DbghelpHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_dbghelp_hooks(registry: &mut HookRegistry) {
    registry.register_library(&DbghelpHookLibrary);
}
