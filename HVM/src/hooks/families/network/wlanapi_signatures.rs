//! Full `HookSignature` table for `wlanapi.dll` functions.
//!
//! Covers Wireless LAN API: handle management, interface enumeration,
// interface queries, scanning, network listing, connection management,
// and memory cleanup.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static WLANAPI_SIGNATURES: &[HookSignature] = &[
    // ── Handle Management ─────────────────────────────────────────────────
    HookSignature {
        module: "wlanapi.dll",
        function: "WlanOpenHandle",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwClientVersion", U32),
            ParamSpec::new("pReserved", GuestPtr),
            ParamSpec::new("pdwNegotiatedVersion", GuestPtr),
            ParamSpec::new("phClientHandle", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wlanapi.dll",
        function: "WlanCloseHandle",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hClientHandle", Handle),
            ParamSpec::new("pReserved", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Interface Enumeration ─────────────────────────────────────────────
    HookSignature {
        module: "wlanapi.dll",
        function: "WlanEnumInterfaces",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hClientHandle", Handle),
            ParamSpec::new("pReserved", GuestPtr),
            ParamSpec::new("ppInterfaceList", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Interface Query ───────────────────────────────────────────────────
    HookSignature {
        module: "wlanapi.dll",
        function: "WlanQueryInterface",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hClientHandle", Handle),
            ParamSpec::new("pInterfaceGuid", GuidPtr),
            ParamSpec::new("OpCode", I32),
            ParamSpec::new("pReserved", GuestPtr),
            ParamSpec::new("pdwDataSize", GuestPtr),
            ParamSpec::new("ppData", GuestPtr),
            ParamSpec::new("pWlanOpcodeValueType", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Scanning ──────────────────────────────────────────────────────────
    HookSignature {
        module: "wlanapi.dll",
        function: "WlanScan",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hClientHandle", Handle),
            ParamSpec::new("pInterfaceGuid", GuidPtr),
            ParamSpec::new("pDot11Ssid", GuestPtr),
            ParamSpec::new("pIeData", GuestPtr),
            ParamSpec::new("dwIeDataSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Available Network List ────────────────────────────────────────────
    HookSignature {
        module: "wlanapi.dll",
        function: "WlanGetAvailableNetworkList",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hClientHandle", Handle),
            ParamSpec::new("pInterfaceGuid", GuidPtr),
            ParamSpec::new("dwFlags", U32),
            ParamSpec::new("pReserved", GuestPtr),
            ParamSpec::new("ppAvailableNetworkList", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Connection Management ─────────────────────────────────────────────
    HookSignature {
        module: "wlanapi.dll",
        function: "WlanConnect",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hClientHandle", Handle),
            ParamSpec::new("pInterfaceGuid", GuidPtr),
            ParamSpec::new("pConnectionParameters", GuestPtr),
            ParamSpec::new("pReserved", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wlanapi.dll",
        function: "WlanDisconnect",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hClientHandle", Handle),
            ParamSpec::new("pInterfaceGuid", GuidPtr),
            ParamSpec::new("pReserved", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Memory Cleanup ────────────────────────────────────────────────────
    HookSignature {
        module: "wlanapi.dll",
        function: "WlanFreeMemory",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pMemory", GuestPtr)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
];
