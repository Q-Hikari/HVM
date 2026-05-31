//! Full `HookSignature` table for `api-ms-win-appmodel-runtime-l1-1-2.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

const MODULE: &str = "api-ms-win-appmodel-runtime-l1-1-2.dll";

pub(super) static APPMODEL_RUNTIME_SIGNATURES: &[HookSignature] = &[
    // ── App Policy ────────────────────────────────────────────────────────
    HookSignature {
        module: MODULE,
        function: "AppPolicyGetProcessTerminationMethod",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("processToken", Handle),
            ParamSpec::with_dir("policy", GuestPtr, Out),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: MODULE,
        function: "AppPolicyGetThreadInitializationType",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("processToken", Handle),
            ParamSpec::with_dir("policy", GuestPtr, Out),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
];
