use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("WinHttpOpen", LogicalAbi::WinApi),
    ("WinHttpConnect", LogicalAbi::WinApi),
    ("WinHttpOpenRequest", LogicalAbi::WinApi),
    ("WinHttpAddRequestHeaders", LogicalAbi::WinApi),
    ("WinHttpSendRequest", LogicalAbi::WinApi),
    ("WinHttpWriteData", LogicalAbi::WinApi),
    ("WinHttpReceiveResponse", LogicalAbi::WinApi),
    ("WinHttpReadData", LogicalAbi::WinApi),
    ("WinHttpQueryDataAvailable", LogicalAbi::WinApi),
    ("WinHttpQueryHeaders", LogicalAbi::WinApi),
    ("WinHttpSetOption", LogicalAbi::WinApi),
    ("WinHttpQueryOption", LogicalAbi::WinApi),
    ("WinHttpSetTimeouts", LogicalAbi::WinApi),
    ("WinHttpGetIEProxyConfigForCurrentUser", LogicalAbi::WinApi),
    ("WinHttpGetProxyForUrl", LogicalAbi::WinApi),
    ("WinHttpCloseHandle", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_winhttp_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("winhttp.dll", &FUNCTIONS);
}
