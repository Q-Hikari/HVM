use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "dnsapi.dll",
        "DnsQuery_A",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dnsapi.dll",
        "DnsQuery_W",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dnsapi.dll",
        "DnsQuery_UTF8",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dnsapi.dll",
        "DnsRecordListFree",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dnsapi.dll",
        "DnsFree",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dnsapi.dll",
        "DnsNameCompare_A",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dnsapi.dll",
        "DnsNameCompare_W",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dnsapi.dll",
        "DnsValidateName_A",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dnsapi.dll",
        "DnsValidateName_W",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "dnsapi.dll",
        "DnsFlushResolverCache",
        0,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct DnsapiHookLibrary;

impl HookLibrary for DnsapiHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_dnsapi_hooks(registry: &mut HookRegistry) {
    registry.register_library(&DnsapiHookLibrary);
}
