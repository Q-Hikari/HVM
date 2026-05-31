use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("CryptRetrieveObjectByUrlA", LogicalAbi::WinApi),
    ("CryptRetrieveObjectByUrlW", LogicalAbi::WinApi),
    ("CryptGetObjectUrl", LogicalAbi::WinApi),
    ("CryptGetTimeValidObject", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_cryptnet_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("cryptnet.dll", &FUNCTIONS);
}
