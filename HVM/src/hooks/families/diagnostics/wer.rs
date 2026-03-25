use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "wer.dll",
        "WerReportCreate",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerReportSetParameter",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerReportAddFile",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerReportSetUIOption",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerReportSubmit",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerReportAddDump",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerReportCloseHandle",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerStoreOpen",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerStoreClose",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerStoreGetFirstReportKey",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerStoreGetNextReportKey",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerFreeString",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerStorePurge",
        0,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerStoreGetReportCount",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "WerStoreGetSizeOnDisk",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "OpenThreadWaitChainSession",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "GetThreadWaitChain",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "CloseThreadWaitChainSession",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wer.dll",
        "RegisterWaitChainCOMCallback",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct WerHookLibrary;

impl HookLibrary for WerHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_wer_hooks(registry: &mut HookRegistry) {
    registry.register_library(&WerHookLibrary);
}
