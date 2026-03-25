use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stdcall_definitions;

const EXPORTS: &[(&str, usize)] = &[
    ("SysAllocString", 1),
    ("SysAllocStringLen", 2),
    ("SysAllocStringByteLen", 2),
    ("SysReAllocString", 2),
    ("SysReAllocStringLen", 3),
    ("SysFreeString", 1),
    ("SysStringLen", 1),
    ("SysStringByteLen", 1),
    ("VariantInit", 1),
    ("VariantClear", 1),
    ("VariantCopy", 2),
    ("VariantChangeType", 4),
    ("VarBstrFromDate", 4),
    ("VarUI4FromStr", 4),
    ("SafeArrayCreate", 3),
    ("SafeArrayCreateVector", 3),
    ("SafeArrayDestroy", 1),
    ("SafeArrayGetDim", 1),
    ("SafeArrayGetElemsize", 1),
    ("SafeArrayAccessData", 2),
    ("SafeArrayUnaccessData", 1),
    ("SafeArrayLock", 1),
    ("SafeArrayUnlock", 1),
    ("SafeArrayGetUBound", 3),
    ("SafeArrayGetLBound", 3),
    ("SafeArrayPutElement", 3),
    ("SafeArrayGetElement", 3),
    ("SafeArrayPtrOfIndex", 3),
    ("LoadTypeLib", 2),
    ("SystemTimeToVariantTime", 2),
    ("VariantTimeToSystemTime", 2),
    ("OleCreateFontIndirect", 3),
    ("ordinal_2", 1),
    ("ordinal_4", 2),
    ("ordinal_6", 1),
    ("ordinal_7", 1),
    ("ordinal_8", 1),
    ("ordinal_9", 1),
    ("ordinal_10", 2),
    ("ordinal_12", 4),
    ("ordinal_15", 3),
    ("ordinal_16", 1),
    ("ordinal_17", 1),
    ("ordinal_18", 1),
    ("ordinal_19", 3),
    ("ordinal_20", 3),
    ("ordinal_21", 1),
    ("ordinal_22", 1),
    ("ordinal_23", 2),
    ("ordinal_24", 1),
    ("ordinal_25", 3),
    ("ordinal_26", 3),
    ("ordinal_114", 4),
    ("ordinal_148", 3),
    ("ordinal_161", 2),
    ("ordinal_184", 2),
    ("ordinal_185", 2),
    ("ordinal_420", 3),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct Oleaut32HookLibrary;

impl HookLibrary for Oleaut32HookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stdcall_definitions("oleaut32.dll", EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_oleaut32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Oleaut32HookLibrary);
}
