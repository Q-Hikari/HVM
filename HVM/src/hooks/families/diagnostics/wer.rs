use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("WerReportCreate", LogicalAbi::WinApi),
    ("WerReportSetParameter", LogicalAbi::WinApi),
    ("WerReportAddFile", LogicalAbi::WinApi),
    ("WerReportSetUIOption", LogicalAbi::WinApi),
    ("WerReportSubmit", LogicalAbi::WinApi),
    ("WerReportAddDump", LogicalAbi::WinApi),
    ("WerReportCloseHandle", LogicalAbi::WinApi),
    ("WerStoreOpen", LogicalAbi::WinApi),
    ("WerStoreClose", LogicalAbi::WinApi),
    ("WerStoreGetFirstReportKey", LogicalAbi::WinApi),
    ("WerStoreGetNextReportKey", LogicalAbi::WinApi),
    ("WerFreeString", LogicalAbi::WinApi),
    ("WerStorePurge", LogicalAbi::WinApi),
    ("WerStoreGetReportCount", LogicalAbi::WinApi),
    ("WerStoreGetSizeOnDisk", LogicalAbi::WinApi),
    ("OpenThreadWaitChainSession", LogicalAbi::WinApi),
    ("GetThreadWaitChain", LogicalAbi::WinApi),
    ("CloseThreadWaitChainSession", LogicalAbi::WinApi),
    ("RegisterWaitChainCOMCallback", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_wer_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("wer.dll", &FUNCTIONS);
}
