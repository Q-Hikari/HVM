use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static SFC_OS_SIGNATURES: &[HookSignature] = &[HookSignature {
    module: "sfc_os.dll",
    function: "SfcIsFileProtected",
    abi: LogicalAbi::WinApi,
    params: &[
        ParamSpec::new("RpcHandle", Handle),
        ParamSpec::new("ProtFileName", PCWStr),
    ],
    ret: ReturnSpec::Bool32,
    flags: HookFlags::empty(),
}];
