//! Full `HookSignature` entries for ntdll.dll functions whose x86 stack
//! layout requires individual 32-bit parameter slots to work correctly with
//! the x86 ABI adapter (which reads `argc` DWORDs regardless of declared
//! parameter widths).
//!
//! For VerSetConditionMask the real parameter list is `(ULONGLONG, DWORD, BYTE)`,
//! but the x86 adapter treats each parameter as a single 4-byte stack slot.
//! Declaring the 64-bit ConditionMask as two U32 parameters keeps the adapter
//! in sync with the actual stack layout.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static VERSION_SIGS: &[HookSignature] = &[HookSignature {
    module: "ntdll.dll",
    function: "VerSetConditionMask",
    abi: LogicalAbi::WinApi,
    params: &[
        ParamSpec::new("ConditionMaskLo", U32),
        ParamSpec::new("ConditionMaskHi", U32),
        ParamSpec::new("TypeMask", U32),
        ParamSpec::new("Condition", U32),
    ],
    ret: ReturnSpec::PointerSizedUInt,
    flags: HookFlags::empty(),
}];
