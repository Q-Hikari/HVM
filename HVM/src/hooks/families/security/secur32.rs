use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("AcquireCredentialsHandleA", LogicalAbi::WinApi),
    ("AcquireCredentialsHandleW", LogicalAbi::WinApi),
    ("FreeCredentialsHandle", LogicalAbi::WinApi),
    ("InitializeSecurityContextA", LogicalAbi::WinApi),
    ("InitializeSecurityContextW", LogicalAbi::WinApi),
    ("AcceptSecurityContext", LogicalAbi::WinApi),
    ("DeleteSecurityContext", LogicalAbi::WinApi),
    ("QueryContextAttributesA", LogicalAbi::WinApi),
    ("QueryContextAttributesW", LogicalAbi::WinApi),
    ("QuerySecurityPackageInfoA", LogicalAbi::WinApi),
    ("QuerySecurityPackageInfoW", LogicalAbi::WinApi),
    ("EnumerateSecurityPackagesA", LogicalAbi::WinApi),
    ("EnumerateSecurityPackagesW", LogicalAbi::WinApi),
    ("FreeContextBuffer", LogicalAbi::WinApi),
    ("EncryptMessage", LogicalAbi::WinApi),
    ("DecryptMessage", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_secur32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("secur32.dll", &FUNCTIONS);
}
