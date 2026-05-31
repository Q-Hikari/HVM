use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("WTSOpenServerA", LogicalAbi::WinApi),
    ("WTSOpenServerW", LogicalAbi::WinApi),
    ("WTSCloseServer", LogicalAbi::WinApi),
    ("WTSEnumerateSessionsA", LogicalAbi::WinApi),
    ("WTSEnumerateSessionsW", LogicalAbi::WinApi),
    ("WTSQuerySessionInformationA", LogicalAbi::WinApi),
    ("WTSQuerySessionInformationW", LogicalAbi::WinApi),
    ("WTSFreeMemory", LogicalAbi::WinApi),
    ("WTSQueryUserToken", LogicalAbi::WinApi),
    ("WTSSendMessageA", LogicalAbi::WinApi),
    ("WTSSendMessageW", LogicalAbi::WinApi),
    ("WTSRegisterSessionNotification", LogicalAbi::WinApi),
    ("WTSUnRegisterSessionNotification", LogicalAbi::WinApi),
    ("WTSDisconnectSession", LogicalAbi::WinApi),
    ("WTSLogoffSession", LogicalAbi::WinApi),
    ("WTSEnumerateProcessesA", LogicalAbi::WinApi),
    ("WTSEnumerateProcessesW", LogicalAbi::WinApi),
    ("WTSEnumerateProcessesExA", LogicalAbi::WinApi),
    ("WTSEnumerateProcessesExW", LogicalAbi::WinApi),
    ("WTSFreeMemoryExA", LogicalAbi::WinApi),
    ("WTSFreeMemoryExW", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_wtsapi32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("wtsapi32.dll", &FUNCTIONS);
}
