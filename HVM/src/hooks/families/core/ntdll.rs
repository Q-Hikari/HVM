use crate::hooks::base::{CallConv, HookDefinition, HookLibrary};
use crate::hooks::registry::HookRegistry;
use crate::tests_support::LoadedTestEngine;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
pub const STATUS_INVALID_FILE_FOR_SECTION: u32 = 0xC000_0020;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_INVALID_PAGE_PROTECTION: u32 = 0xC000_0045;

/// Collects the `ntdll.dll` hook definitions currently backed by Rust code.
#[derive(Debug, Default, Clone, Copy)]
pub struct NtdllHookLibrary;

impl HookLibrary for NtdllHookLibrary {
    fn collect(&self) -> Vec<HookDefinition> {
        vec![
            definition("DbgUiSetThreadDebugObject", 1),
            definition("NtContinue", 2),
            definition("NtGetContextThread", 2),
            definition("NtClose", 1),
            definition("NtAllocateVirtualMemory", 6),
            definition("NtCreateSection", 7),
            definition("NtCreateThreadEx", 11),
            definition("NtDuplicateObject", 7),
            definition("NtFreeVirtualMemory", 4),
            definition("NtMapViewOfSection", 10),
            definition("NtOpenProcess", 4),
            definition("NtProtectVirtualMemory", 5),
            definition("NtQueryInformationProcess", 5),
            definition("NtRemoveProcessDebug", 2),
            definition("NtReadVirtualMemory", 5),
            definition("NtQuerySystemInformation", 4),
            definition("NtQueryVirtualMemory", 6),
            definition("NtQueueApcThread", 5),
            definition("NtSetContextThread", 2),
            definition("NtUnmapViewOfSection", 2),
            definition("NtWriteVirtualMemory", 5),
            definition("RtlAllocateHeap", 3),
            definition("RtlCaptureContext", 1),
            definition("RtlFillMemory", 3),
            definition("RtlFreeHeap", 3),
            definition("RtlGetVersion", 1),
            definition("RtlCreateUserThread", 10),
            definition("RtlLookupFunctionEntry", 3),
            definition("RtlPcToFileHeader", 2),
            definition("RtlRestoreContext", 2),
            definition("RtlUnwind", 4),
            definition("RtlUnwindEx", 6),
            definition("RtlVirtualUnwind", 8),
            definition("RtlZeroMemory", 2),
            definition("ZwGetContextThread", 2),
            definition("ZwAllocateVirtualMemory", 6),
            definition("ZwCreateSection", 7),
            definition("ZwCreateThreadEx", 11),
            definition("ZwContinue", 2),
            definition("ZwFreeVirtualMemory", 4),
            definition("ZwMapViewOfSection", 10),
            definition("ZwOpenProcess", 4),
            definition("ZwProtectVirtualMemory", 5),
            definition("ZwQueryInformationProcess", 5),
            definition("ZwReadVirtualMemory", 5),
            definition("ZwQuerySystemInformation", 4),
            definition("ZwQueryVirtualMemory", 6),
            definition("ZwQueueApcThread", 5),
            definition("ZwSetInformationKey", 4),
            definition("ZwSetContextThread", 2),
            definition("ZwUnmapViewOfSection", 2),
            definition("ZwWriteVirtualMemory", 5),
        ]
    }
}

/// Registers the currently supported `ntdll.dll` hook definitions.
pub fn register_ntdll_hooks(registry: &mut HookRegistry) {
    registry.register_library(&NtdllHookLibrary);
}

/// Exposes test-only `ntdll.dll` helpers over the loaded Rust runtime scaffold.
#[derive(Debug)]
pub struct NtdllApi<'a> {
    engine: &'a mut LoadedTestEngine,
}

impl<'a> NtdllApi<'a> {
    /// Builds an `ntdll.dll` helper bound to one loaded test engine.
    pub(crate) fn new(engine: &'a mut LoadedTestEngine) -> Self {
        Self { engine }
    }

    /// Queues one APC for a thread handle and returns an NTSTATUS-style result code.
    pub fn queue_apc_thread_for_test(
        &mut self,
        thread_handle: u32,
        routine: u64,
        parameter: u64,
    ) -> u32 {
        if self
            .engine
            .scheduler_mut()
            .queue_user_apc(thread_handle, routine, parameter)
            .is_some()
        {
            STATUS_SUCCESS
        } else {
            STATUS_INVALID_HANDLE
        }
    }
}

fn definition(function: &'static str, argc: usize) -> HookDefinition {
    HookDefinition {
        module: "ntdll.dll",
        function,
        argc,
        call_conv: CallConv::Stdcall,
    }
}
