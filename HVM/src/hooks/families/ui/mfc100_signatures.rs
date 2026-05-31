use crate::hooks::signature::{HookSignature, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi};

pub(super) static MFC100_SIGNATURES: &[HookSignature] = &[HookSignature {
    module: "mfc100.dll",
    function: "ordinal_1895",
    abi: LogicalAbi::WinApi,
    params: &[],
    ret: ReturnSpec::PointerSizedUInt,
    flags: HookFlags::empty(),
}];
