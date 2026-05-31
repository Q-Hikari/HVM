use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("SetupDiGetClassDevsA", LogicalAbi::WinApi),
    ("SetupDiGetClassDevsW", LogicalAbi::WinApi),
    ("SetupDiDestroyDeviceInfoList", LogicalAbi::WinApi),
    ("SetupDiEnumDeviceInfo", LogicalAbi::WinApi),
    ("SetupDiGetDeviceRegistryPropertyA", LogicalAbi::WinApi),
    ("SetupDiGetDeviceRegistryPropertyW", LogicalAbi::WinApi),
    ("SetupDiGetDeviceInstanceIdA", LogicalAbi::WinApi),
    ("SetupDiGetDeviceInstanceIdW", LogicalAbi::WinApi),
    ("SetupDiOpenDevRegKey", LogicalAbi::WinApi),
    ("SetupDiEnumDeviceInterfaces", LogicalAbi::WinApi),
    ("SetupDiGetDeviceInterfaceDetailA", LogicalAbi::WinApi),
    ("SetupDiGetDeviceInterfaceDetailW", LogicalAbi::WinApi),
    ("SetupDiClassGuidsFromNameA", LogicalAbi::WinApi),
    ("SetupDiClassGuidsFromNameW", LogicalAbi::WinApi),
    ("SetupDiGetINFClassA", LogicalAbi::WinApi),
    ("SetupDiGetINFClassW", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_setupapi_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("setupapi.dll", &FUNCTIONS);
}
