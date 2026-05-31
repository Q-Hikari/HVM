//! Full `HookSignature` table for `netutils.dll` functions.
//!
//! Covers Network Utility API: buffer management and remote name validation.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static NETUTILS_SIGNATURES: &[HookSignature] = &[
    // ── Buffer Management ─────────────────────────────────────────────────
    HookSignature {
        module: "netutils.dll",
        function: "NetApiBufferFree",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("Buffer", GuestPtr)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Remote Name Validation ────────────────────────────────────────────
    HookSignature {
        module: "netutils.dll",
        function: "NetpIsRemote",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("UncName", PCWStr),
            ParamSpec::new("IsRemoteFlag", GuestPtr),
            ParamSpec::new("pIsLocal", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "netutils.dll",
        function: "NetpIsRemoteNameValid",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("UncName", PCWStr),
            ParamSpec::new("IsValid", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
];
