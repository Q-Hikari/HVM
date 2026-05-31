use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("UuidCreate", LogicalAbi::WinApi),
    ("UuidCreateSequential", LogicalAbi::WinApi),
    ("UuidCompare", LogicalAbi::WinApi),
    ("UuidEqual", LogicalAbi::WinApi),
    ("UuidIsNil", LogicalAbi::WinApi),
    ("UuidHash", LogicalAbi::WinApi),
    ("UuidFromStringA", LogicalAbi::WinApi),
    ("UuidFromStringW", LogicalAbi::WinApi),
    ("UuidToStringA", LogicalAbi::WinApi),
    ("UuidToStringW", LogicalAbi::WinApi),
    ("RpcStringFreeA", LogicalAbi::WinApi),
    ("RpcStringFreeW", LogicalAbi::WinApi),
    ("RpcBindingFromStringBindingA", LogicalAbi::WinApi),
    ("RpcBindingFromStringBindingW", LogicalAbi::WinApi),
    ("RpcBindingFree", LogicalAbi::WinApi),
    ("RpcBindingSetAuthInfoA", LogicalAbi::WinApi),
    ("RpcBindingSetAuthInfoW", LogicalAbi::WinApi),
    ("RpcBindingSetAuthInfoExW", LogicalAbi::WinApi),
    ("RpcStringBindingComposeA", LogicalAbi::WinApi),
    ("RpcStringBindingComposeW", LogicalAbi::WinApi),
    ("RpcStringBindingParseA", LogicalAbi::WinApi),
    ("RpcStringBindingParseW", LogicalAbi::WinApi),
    ("I_RpcAllocate", LogicalAbi::WinApi),
    ("I_RpcFree", LogicalAbi::WinApi),
    ("NdrOleAllocate", LogicalAbi::WinApi),
    ("NdrOleFree", LogicalAbi::WinApi),
    ("NdrAsyncClientCall", LogicalAbi::WinApi),
    ("RpcAsyncInitializeHandle", LogicalAbi::WinApi),
    ("RpcAsyncCompleteCall", LogicalAbi::WinApi),
    ("RpcRaiseException", LogicalAbi::WinApi),
    ("DceErrorInqTextA", LogicalAbi::WinApi),
    ("DceErrorInqTextW", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_rpcrt4_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("rpcrt4.dll", &FUNCTIONS);
    registry.register_signatures(super::rpcrt4_signatures::RPCRT4_SIGNATURES);
}
