use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("URLDownloadToFileA", LogicalAbi::WinApi),
    ("URLDownloadToFileW", LogicalAbi::WinApi),
    ("URLDownloadToCacheFileA", LogicalAbi::WinApi),
    ("URLDownloadToCacheFileW", LogicalAbi::WinApi),
    ("DeleteUrlCacheEntryA", LogicalAbi::WinApi),
    ("DeleteUrlCacheEntryW", LogicalAbi::WinApi),
    ("ObtainUserAgentString", LogicalAbi::WinApi),
    ("CoInternetSetFeatureEnabled", LogicalAbi::WinApi),
    ("CreateUri", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_urlmon_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("urlmon.dll", &FUNCTIONS);
}
