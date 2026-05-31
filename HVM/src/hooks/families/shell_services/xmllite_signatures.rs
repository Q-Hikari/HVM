//! Full `HookSignature` table for `xmllite.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static XMLLITE_SIGNATURES: &[HookSignature] = &[
    // ── XML Writer factory ───────────────────────────────────────────────
    HookSignature {
        module: "xmllite.dll",
        function: "CreateXmlWriter",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::new("ppv", GuestPtr),
            ParamSpec::new("pMalloc", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
];
