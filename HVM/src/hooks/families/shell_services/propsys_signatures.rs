//! Full `HookSignature` table for `propsys.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static PROPSYS_SIGNATURES: &[HookSignature] = &[
    // ── PropVariant conversion helpers ───────────────────────────────────
    HookSignature {
        module: "propsys.dll",
        function: "PropVariantToString",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("propvar", GuestPtr),
            ParamSpec::new("psz", PWStr),
            ParamSpec::new("cch", U32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "propsys.dll",
        function: "PropVariantToUInt32",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("propvar", GuestPtr),
            ParamSpec::new("puiVal", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "propsys.dll",
        function: "PropVariantToUInt32WithDefault",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("propvar", GuestPtr),
            ParamSpec::new("uiDefault", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
];
