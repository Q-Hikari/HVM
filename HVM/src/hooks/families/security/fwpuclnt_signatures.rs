//! Full `HookSignature` table for `fwpuclnt.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static FWPUCLNT_SIGNATURES: &[HookSignature] = &[
    // ── WFP Engine ────────────────────────────────────────────────────────
    HookSignature {
        module: "fwpuclnt.dll",
        function: "FwpmEngineOpen0",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("serverName", PCWStr),
            ParamSpec::new("authnService", U32),
            ParamSpec::new("authIdentity", GuestPtr),
            ParamSpec::new("session", GuestPtr),
            ParamSpec::with_dir("engineHandle", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "fwpuclnt.dll",
        function: "FwpmEngineClose0",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("engineHandle", Handle)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── WFP Transaction ───────────────────────────────────────────────────
    HookSignature {
        module: "fwpuclnt.dll",
        function: "FwpmTransactionBegin0",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("engineHandle", Handle),
            ParamSpec::new("flags", Hex32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "fwpuclnt.dll",
        function: "FwpmTransactionCommit0",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("engineHandle", Handle)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── WFP Sub-Layer / Callout / Filter ───────────────────────────────────
    HookSignature {
        module: "fwpuclnt.dll",
        function: "FwpmSubLayerAdd0",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("engineHandle", Handle),
            ParamSpec::new("subLayer", GuestPtr),
            ParamSpec::new("sd", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "fwpuclnt.dll",
        function: "FwpmCalloutAdd0",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("engineHandle", Handle),
            ParamSpec::new("callout", GuestPtr),
            ParamSpec::new("sd", GuestPtr),
            ParamSpec::with_dir("id", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "fwpuclnt.dll",
        function: "FwpmFilterAdd0",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("engineHandle", Handle),
            ParamSpec::new("filter", GuestPtr),
            ParamSpec::new("sd", GuestPtr),
            ParamSpec::with_dir("id", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
];
