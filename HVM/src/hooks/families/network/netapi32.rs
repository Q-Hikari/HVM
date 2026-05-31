use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("Netbios", LogicalAbi::WinApi),
    ("NetApiBufferFree", LogicalAbi::WinApi),
    ("NetGetJoinInformation", LogicalAbi::WinApi),
    ("NetGetDCName", LogicalAbi::WinApi),
    ("NetGetAnyDCName", LogicalAbi::WinApi),
    ("NetWkstaGetInfo", LogicalAbi::WinApi),
    ("NetUserEnum", LogicalAbi::WinApi),
    ("NetUserGetInfo", LogicalAbi::WinApi),
    ("NetUserAdd", LogicalAbi::WinApi),
    ("NetUserSetInfo", LogicalAbi::WinApi),
    ("NetGroupEnum", LogicalAbi::WinApi),
    ("NetGroupGetInfo", LogicalAbi::WinApi),
    ("NetUserGetGroups", LogicalAbi::WinApi),
    ("NetGroupGetUsers", LogicalAbi::WinApi),
    ("NetUseEnum", LogicalAbi::WinApi),
    ("NetUseAdd", LogicalAbi::WinApi),
    ("NetUseDel", LogicalAbi::WinApi),
    ("NetUseGetInfo", LogicalAbi::WinApi),
    ("NetFileEnum", LogicalAbi::WinApi),
    ("NetFileGetInfo", LogicalAbi::WinApi),
    ("NetFileClose", LogicalAbi::WinApi),
    ("NetConnectionEnum", LogicalAbi::WinApi),
    ("NetShareCheck", LogicalAbi::WinApi),
    ("NetRemoteTOD", LogicalAbi::WinApi),
    ("NetShareEnum", LogicalAbi::WinApi),
    ("NetShareGetInfo", LogicalAbi::WinApi),
    ("NetSessionEnum", LogicalAbi::WinApi),
    ("NetWkstaUserEnum", LogicalAbi::WinApi),
    ("NetLocalGroupEnum", LogicalAbi::WinApi),
    ("NetUserGetLocalGroups", LogicalAbi::WinApi),
    ("NetLocalGroupGetMembers", LogicalAbi::WinApi),
    ("NetLocalGroupAddMembers", LogicalAbi::WinApi),
    ("NetLocalGroupDelMembers", LogicalAbi::WinApi),
    ("NetLocalGroupGetInfo", LogicalAbi::WinApi),
    ("NetServerGetInfo", LogicalAbi::WinApi),
    ("NetServerEnum", LogicalAbi::WinApi),
    ("DsRoleGetPrimaryDomainInformation", LogicalAbi::WinApi),
    ("DsGetDcNameA", LogicalAbi::WinApi),
    ("DsGetDcNameW", LogicalAbi::WinApi),
    ("DsEnumerateDomainTrustsA", LogicalAbi::WinApi),
    ("DsEnumerateDomainTrustsW", LogicalAbi::WinApi),
    ("DsRoleFreeMemory", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_netapi32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("netapi32.dll", &FUNCTIONS);
}
