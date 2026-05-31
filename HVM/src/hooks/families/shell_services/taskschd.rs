use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("DllCanUnloadNow", LogicalAbi::WinApi),
    ("DllGetClassObject", LogicalAbi::WinApi),
    ("DllRegisterServer", LogicalAbi::WinApi),
    ("DllUnregisterServer", LogicalAbi::WinApi),
    ("DllInstall", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_taskschd_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("taskschd.dll", &FUNCTIONS);
}
