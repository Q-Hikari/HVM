use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;
use crate::tests_support::LoadedTestEngine;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;
pub const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub const STATUS_INVALID_FILE_FOR_SECTION: u32 = 0xC000_0020;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_INVALID_PAGE_PROTECTION: u32 = 0xC000_0045;
pub const STATUS_PROCEDURE_NOT_FOUND: u32 = 0xC000_007A;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;

mod stubs_1;
mod stubs_2;

static ALL_STUBS: &[&[(&str, LogicalAbi)]] = &[stubs_1::STUBS_1, stubs_2::STUBS_2];

/// Registers the currently supported `ntdll.dll` hook definitions.
pub fn register_ntdll_hooks(registry: &mut HookRegistry) {
    for stubs in ALL_STUBS {
        registry.register_function_stubs("ntdll.dll", stubs);
    }
    super::ntdll_signatures::register_all(registry);
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
