use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stdcall_definitions;

const EXPORTS: &[(&str, usize)] = &[
    ("CLSIDFromProgID", 2),
    ("CLSIDFromString", 2),
    ("CoCreateGuid", 1),
    ("CoCreateFreeThreadedMarshaler", 2),
    ("CoCreateInstance", 5),
    ("CoDisconnectObject", 2),
    ("CoFreeUnusedLibraries", 0),
    ("CoGetClassObject", 5),
    ("CoInitialize", 1),
    ("CoInitializeEx", 2),
    ("CoLockObjectExternal", 3),
    ("CoRegisterMessageFilter", 2),
    ("CoRevokeClassObject", 1),
    ("CoTaskMemAlloc", 1),
    ("CoTaskMemFree", 1),
    ("CoTaskMemRealloc", 2),
    ("CoUninitialize", 0),
    ("CreateILockBytesOnHGlobal", 3),
    ("CreateStreamOnHGlobal", 3),
    ("DoDragDrop", 4),
    ("IsAccelerator", 4),
    ("OleCreateMenuDescriptor", 2),
    ("OleDestroyMenuDescriptor", 1),
    ("OleDuplicateData", 3),
    ("OleFlushClipboard", 0),
    ("OleGetClipboard", 1),
    ("OleInitialize", 1),
    ("OleIsCurrentClipboard", 1),
    ("OleLockRunning", 3),
    ("OleTranslateAccelerator", 3),
    ("OleUninitialize", 0),
    ("RegisterDragDrop", 2),
    ("ReleaseStgMedium", 1),
    ("RevokeDragDrop", 1),
    ("StgCreateDocfileOnILockBytes", 4),
    ("StgOpenStorageOnILockBytes", 6),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ole32HookLibrary;

impl HookLibrary for Ole32HookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stdcall_definitions("ole32.dll", EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_ole32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Ole32HookLibrary);
}
