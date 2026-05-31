use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("WSAStartup", LogicalAbi::WinApi),
    ("WSACleanup", LogicalAbi::WinApi),
    ("WSAGetLastError", LogicalAbi::WinApi),
    ("WSASetLastError", LogicalAbi::WinApi),
    ("WSACreateEvent", LogicalAbi::WinApi),
    ("WSACloseEvent", LogicalAbi::WinApi),
    ("WSAEnumNetworkEvents", LogicalAbi::WinApi),
    ("WSAEventSelect", LogicalAbi::WinApi),
    ("WSAResetEvent", LogicalAbi::WinApi),
    ("WSAWaitForMultipleEvents", LogicalAbi::WinApi),
    ("WSAIoctl", LogicalAbi::WinApi),
    ("WSARecv", LogicalAbi::WinApi),
    ("WSASend", LogicalAbi::WinApi),
    ("WSASocketW", LogicalAbi::WinApi),
    ("ordinal_1", LogicalAbi::WinApi),
    ("ordinal_2", LogicalAbi::WinApi),
    ("ordinal_3", LogicalAbi::WinApi),
    ("ordinal_4", LogicalAbi::WinApi),
    ("ordinal_5", LogicalAbi::WinApi),
    ("ordinal_6", LogicalAbi::WinApi),
    ("ordinal_7", LogicalAbi::WinApi),
    ("ordinal_8", LogicalAbi::WinApi),
    ("ordinal_9", LogicalAbi::WinApi),
    ("ordinal_10", LogicalAbi::WinApi),
    ("ordinal_11", LogicalAbi::WinApi),
    ("ordinal_12", LogicalAbi::WinApi),
    ("ordinal_13", LogicalAbi::WinApi),
    ("ordinal_14", LogicalAbi::WinApi),
    ("ordinal_15", LogicalAbi::WinApi),
    ("ordinal_16", LogicalAbi::WinApi),
    ("ordinal_17", LogicalAbi::WinApi),
    ("ordinal_18", LogicalAbi::WinApi),
    ("ordinal_19", LogicalAbi::WinApi),
    ("ordinal_20", LogicalAbi::WinApi),
    ("ordinal_21", LogicalAbi::WinApi),
    ("ordinal_22", LogicalAbi::WinApi),
    ("ordinal_23", LogicalAbi::WinApi),
    ("ordinal_51", LogicalAbi::WinApi),
    ("ordinal_52", LogicalAbi::WinApi),
    ("ordinal_53", LogicalAbi::WinApi),
    ("ordinal_55", LogicalAbi::WinApi),
    ("ordinal_56", LogicalAbi::WinApi),
    ("ordinal_57", LogicalAbi::WinApi),
    ("ordinal_71", LogicalAbi::WinApi),
    ("ordinal_76", LogicalAbi::WinApi),
    ("ordinal_83", LogicalAbi::WinApi),
    ("ordinal_111", LogicalAbi::WinApi),
    ("ordinal_112", LogicalAbi::WinApi),
    ("ordinal_115", LogicalAbi::WinApi),
    ("ordinal_116", LogicalAbi::WinApi),
    ("ordinal_151", LogicalAbi::WinApi),
    ("socket", LogicalAbi::WinApi),
    ("closesocket", LogicalAbi::WinApi),
    ("bind", LogicalAbi::WinApi),
    ("connect", LogicalAbi::WinApi),
    ("listen", LogicalAbi::WinApi),
    ("accept", LogicalAbi::WinApi),
    ("getpeername", LogicalAbi::WinApi),
    ("getsockname", LogicalAbi::WinApi),
    ("send", LogicalAbi::WinApi),
    ("recv", LogicalAbi::WinApi),
    ("sendto", LogicalAbi::WinApi),
    ("recvfrom", LogicalAbi::WinApi),
    ("shutdown", LogicalAbi::WinApi),
    ("select", LogicalAbi::WinApi),
    ("ioctlsocket", LogicalAbi::WinApi),
    ("setsockopt", LogicalAbi::WinApi),
    ("getsockopt", LogicalAbi::WinApi),
    ("htons", LogicalAbi::WinApi),
    ("ntohs", LogicalAbi::WinApi),
    ("htonl", LogicalAbi::WinApi),
    ("ntohl", LogicalAbi::WinApi),
    ("inet_addr", LogicalAbi::WinApi),
    ("inet_ntop", LogicalAbi::WinApi),
    ("inet_ntoa", LogicalAbi::WinApi),
    ("gethostbyaddr", LogicalAbi::WinApi),
    ("gethostbyname", LogicalAbi::WinApi),
    ("getprotobyname", LogicalAbi::WinApi),
    ("getservbyname", LogicalAbi::WinApi),
    ("getservbyport", LogicalAbi::WinApi),
    ("gethostname", LogicalAbi::WinApi),
    ("getaddrinfo", LogicalAbi::WinApi),
    ("freeaddrinfo", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_ws2_32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("ws2_32.dll", &FUNCTIONS);
}

#[cfg(test)]
mod tests {
    use super::register_ws2_32_hooks;
    use crate::hooks::registry::HookRegistry;

    #[test]
    fn registers_ws2_named_exports_used_by_runtime_dispatch() {
        let mut registry = HookRegistry::for_tests();
        register_ws2_32_hooks(&mut registry);

        for function in [
            "getpeername",
            "getsockname",
            "sendto",
            "recvfrom",
            "inet_ntop",
            "gethostbyaddr",
            "gethostname",
            "getprotobyname",
            "getservbyname",
            "getservbyport",
        ] {
            assert!(
                registry.has_signature_for("ws2_32.dll", function),
                "missing ws2_32 registration for {function}"
            );
        }
    }
}
