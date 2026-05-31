use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("SymInitialize", LogicalAbi::WinApi),
    ("SymInitializeW", LogicalAbi::WinApi),
    ("SymCleanup", LogicalAbi::WinApi),
    ("SymSetOptions", LogicalAbi::WinApi),
    ("SymGetOptions", LogicalAbi::WinApi),
    ("SymLoadModuleEx", LogicalAbi::WinApi),
    ("SymLoadModuleExW", LogicalAbi::WinApi),
    ("SymGetModuleBase64", LogicalAbi::WinApi),
    ("SymFunctionTableAccess64", LogicalAbi::WinApi),
    ("SymRefreshModuleList", LogicalAbi::WinApi),
    ("SymFromAddr", LogicalAbi::WinApi),
    ("SymFromAddrW", LogicalAbi::WinApi),
    ("SymGetLineFromAddr64", LogicalAbi::WinApi),
    ("UnDecorateSymbolName", LogicalAbi::WinApi),
    ("MiniDumpWriteDump", LogicalAbi::WinApi),
    ("StackWalk64", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_dbghelp_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("dbghelp.dll", &FUNCTIONS);
}
