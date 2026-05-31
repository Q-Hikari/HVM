//! Full `HookSignature` table for `oledlg.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static OLEDLG_SIGNATURES: &[HookSignature] = &[HookSignature {
    module: "oledlg.dll",
    function: "OleUIBusyW",
    abi: LogicalAbi::WinApi,
    params: &[ParamSpec::new("lpBusyInfo", GuestPtr)],
    ret: ReturnSpec::U32,
    flags: HookFlags::empty(),
}];
