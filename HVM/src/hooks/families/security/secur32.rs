use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "secur32.dll",
        "AcquireCredentialsHandleA",
        9,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "AcquireCredentialsHandleW",
        9,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "FreeCredentialsHandle",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "InitializeSecurityContextA",
        12,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "InitializeSecurityContextW",
        12,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "AcceptSecurityContext",
        9,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "DeleteSecurityContext",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "QueryContextAttributesA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "QueryContextAttributesW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "QuerySecurityPackageInfoA",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "QuerySecurityPackageInfoW",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "EnumerateSecurityPackagesA",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "EnumerateSecurityPackagesW",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "FreeContextBuffer",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "EncryptMessage",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "secur32.dll",
        "DecryptMessage",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct Secur32HookLibrary;

impl HookLibrary for Secur32HookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_secur32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Secur32HookLibrary);
}
