use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("DnsQuery_A", LogicalAbi::WinApi),
    ("DnsQuery_W", LogicalAbi::WinApi),
    ("DnsQuery_UTF8", LogicalAbi::WinApi),
    ("DnsRecordListFree", LogicalAbi::WinApi),
    ("DnsFree", LogicalAbi::WinApi),
    ("DnsNameCompare_A", LogicalAbi::WinApi),
    ("DnsNameCompare_W", LogicalAbi::WinApi),
    ("DnsValidateName_A", LogicalAbi::WinApi),
    ("DnsValidateName_W", LogicalAbi::WinApi),
    ("DnsFlushResolverCache", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_dnsapi_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("dnsapi.dll", &FUNCTIONS);
}
