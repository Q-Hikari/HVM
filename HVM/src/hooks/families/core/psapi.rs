use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS_PSAPI_DLL: &[(&str, LogicalAbi)] = &[
    ("EnumProcesses", LogicalAbi::WinApi),
    ("EnumProcessModules", LogicalAbi::WinApi),
    ("EnumProcessModulesEx", LogicalAbi::WinApi),
    ("GetModuleBaseNameA", LogicalAbi::WinApi),
    ("GetModuleBaseNameW", LogicalAbi::WinApi),
    ("GetModuleFileNameExA", LogicalAbi::WinApi),
    ("GetModuleFileNameExW", LogicalAbi::WinApi),
    ("GetModuleInformation", LogicalAbi::WinApi),
    ("GetProcessImageFileNameA", LogicalAbi::WinApi),
    ("GetProcessImageFileNameW", LogicalAbi::WinApi),
    ("GetMappedFileNameA", LogicalAbi::WinApi),
    ("GetMappedFileNameW", LogicalAbi::WinApi),
    ("EmptyWorkingSet", LogicalAbi::WinApi),
    ("GetProcessMemoryInfo", LogicalAbi::WinApi),
];

static FUNCTIONS_KERNEL32_DLL: &[(&str, LogicalAbi)] = &[
    ("K32EnumProcessModules", LogicalAbi::WinApi),
    ("K32EnumProcessModulesEx", LogicalAbi::WinApi),
    ("K32GetModuleBaseNameA", LogicalAbi::WinApi),
    ("K32GetModuleBaseNameW", LogicalAbi::WinApi),
    ("K32GetModuleFileNameExA", LogicalAbi::WinApi),
    ("K32GetModuleFileNameExW", LogicalAbi::WinApi),
    ("K32GetModuleInformation", LogicalAbi::WinApi),
    ("K32GetProcessMemoryInfo", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_psapi_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("psapi.dll", &FUNCTIONS_PSAPI_DLL);
    registry.register_function_stubs("kernel32.dll", &FUNCTIONS_KERNEL32_DLL);
}
