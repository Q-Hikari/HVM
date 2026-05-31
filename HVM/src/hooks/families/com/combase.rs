use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("CoInitializeEx", LogicalAbi::WinApi),
    ("CoUninitialize", LogicalAbi::WinApi),
    ("CoCreateGuid", LogicalAbi::WinApi),
    ("StringFromGUID2", LogicalAbi::WinApi),
    ("IIDFromString", LogicalAbi::WinApi),
    ("CLSIDFromString", LogicalAbi::WinApi),
    ("StringFromIID", LogicalAbi::WinApi),
    ("StringFromCLSID", LogicalAbi::WinApi),
    ("CoTaskMemAlloc", LogicalAbi::WinApi),
    ("CoTaskMemFree", LogicalAbi::WinApi),
    ("CoTaskMemRealloc", LogicalAbi::WinApi),
    ("CoIncrementMTAUsage", LogicalAbi::WinApi),
    ("CoDecrementMTAUsage", LogicalAbi::WinApi),
    ("WindowsCreateString", LogicalAbi::WinApi),
    ("WindowsDeleteString", LogicalAbi::WinApi),
    ("WindowsDuplicateString", LogicalAbi::WinApi),
    ("WindowsGetStringLen", LogicalAbi::WinApi),
    ("WindowsGetStringRawBuffer", LogicalAbi::WinApi),
    ("WindowsIsStringEmpty", LogicalAbi::WinApi),
    ("RoInitialize", LogicalAbi::WinApi),
    ("RoUninitialize", LogicalAbi::WinApi),
    ("RoGetActivationFactory", LogicalAbi::WinApi),
    ("CoCreateInstance", LogicalAbi::WinApi),
    ("CoGetClassObject", LogicalAbi::WinApi),
    ("PropVariantClear", LogicalAbi::WinApi),
    ("CoGetMalloc", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_combase_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("combase.dll", &FUNCTIONS);
    registry.register_signatures(super::combase_signatures::COMBASE_SIGNATURES);
}
