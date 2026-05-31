//! Full `HookSignature` table for `iphlpapi.dll` functions.
//!
//! Covers IP Helper API: network interface queries, adapter information,
//! network parameters, and TCP/UDP/ARP table retrieval.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static IPHLPAPI_SIGNATURES: &[HookSignature] = &[
    // ── Interface Queries ─────────────────────────────────────────────────
    HookSignature {
        module: "iphlpapi.dll",
        function: "GetBestInterface",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwDestAddr", U32),
            ParamSpec::with_dir("pdwBestIfIndex", GuestPtr, Out),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "iphlpapi.dll",
        function: "GetNumberOfInterfaces",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::with_dir("pdwNumIf", GuestPtr, Out)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "iphlpapi.dll",
        function: "GetFriendlyIfIndex",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("IfIndex", U32)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Adapter Information ───────────────────────────────────────────────
    HookSignature {
        module: "iphlpapi.dll",
        function: "GetAdaptersInfo",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pAdapterInfo", GuestPtr),
            ParamSpec::with_dir("pOutBufLen", GuestPtr, InOut),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Network Parameters ────────────────────────────────────────────────
    HookSignature {
        module: "iphlpapi.dll",
        function: "GetNetworkParams",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pFixedInfo", GuestPtr),
            ParamSpec::with_dir("pOutBufLen", GuestPtr, InOut),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Adapter Addresses ─────────────────────────────────────────────────
    HookSignature {
        module: "iphlpapi.dll",
        function: "GetAdaptersAddresses",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("Family", U32),
            ParamSpec::new("Flags", U32),
            ParamSpec::new("Reserved", GuestPtr),
            ParamSpec::new("pAdapterAddresses", GuestPtr),
            ParamSpec::with_dir("pOutBufLen", GuestPtr, InOut),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── TCP Table ─────────────────────────────────────────────────────────
    HookSignature {
        module: "iphlpapi.dll",
        function: "GetExtendedTcpTable",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pTcpTable", GuestPtr),
            ParamSpec::with_dir("pdwSize", GuestPtr, InOut),
            ParamSpec::new("bOrder", Bool32),
            ParamSpec::new("ulAf", U32),
            ParamSpec::new("TableClass", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "iphlpapi.dll",
        function: "GetTcpTable",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pTcpTable", GuestPtr),
            ParamSpec::with_dir("pdwSize", GuestPtr, InOut),
            ParamSpec::new("bOrder", Bool32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── UDP Table ─────────────────────────────────────────────────────────
    HookSignature {
        module: "iphlpapi.dll",
        function: "GetUdpTable",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pUdpTable", GuestPtr),
            ParamSpec::with_dir("pdwSize", GuestPtr, InOut),
            ParamSpec::new("bOrder", Bool32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── ARP Table ─────────────────────────────────────────────────────────
    HookSignature {
        module: "iphlpapi.dll",
        function: "GetIpNetTable",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pIpNetTable", GuestPtr),
            ParamSpec::with_dir("pdwSize", GuestPtr, InOut),
            ParamSpec::new("bOrder", Bool32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
];
