use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("InternetOpenA", LogicalAbi::WinApi),
    ("InternetOpenW", LogicalAbi::WinApi),
    ("InternetConnectA", LogicalAbi::WinApi),
    ("InternetConnectW", LogicalAbi::WinApi),
    ("InternetOpenUrlA", LogicalAbi::WinApi),
    ("InternetOpenUrlW", LogicalAbi::WinApi),
    ("HttpOpenRequestA", LogicalAbi::WinApi),
    ("HttpOpenRequestW", LogicalAbi::WinApi),
    ("HttpSendRequestA", LogicalAbi::WinApi),
    ("HttpSendRequestW", LogicalAbi::WinApi),
    ("InternetCanonicalizeUrlA", LogicalAbi::WinApi),
    ("InternetCanonicalizeUrlW", LogicalAbi::WinApi),
    ("InternetReadFile", LogicalAbi::WinApi),
    ("InternetCloseHandle", LogicalAbi::WinApi),
    ("InternetSetOptionA", LogicalAbi::WinApi),
    ("InternetSetOptionW", LogicalAbi::WinApi),
    ("InternetQueryOptionA", LogicalAbi::WinApi),
    ("InternetQueryOptionW", LogicalAbi::WinApi),
    ("InternetCrackUrlA", LogicalAbi::WinApi),
    ("InternetCrackUrlW", LogicalAbi::WinApi),
    ("InternetGetConnectedState", LogicalAbi::WinApi),
    ("InternetQueryDataAvailable", LogicalAbi::WinApi),
    ("HttpQueryInfoA", LogicalAbi::WinApi),
    ("HttpQueryInfoW", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_wininet_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("wininet.dll", &FUNCTIONS);
}
