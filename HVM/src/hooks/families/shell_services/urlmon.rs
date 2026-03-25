use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "urlmon.dll",
        "URLDownloadToFileA",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "urlmon.dll",
        "URLDownloadToFileW",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "urlmon.dll",
        "URLDownloadToCacheFileA",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "urlmon.dll",
        "URLDownloadToCacheFileW",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "urlmon.dll",
        "DeleteUrlCacheEntryA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "urlmon.dll",
        "DeleteUrlCacheEntryW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "urlmon.dll",
        "ObtainUserAgentString",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "urlmon.dll",
        "CoInternetSetFeatureEnabled",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct UrlmonHookLibrary;

impl HookLibrary for UrlmonHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_urlmon_hooks(registry: &mut HookRegistry) {
    registry.register_library(&UrlmonHookLibrary);
}
