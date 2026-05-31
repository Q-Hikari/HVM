//! Full `HookSignature` table for `rasapi32.dll` functions.
//!
//! Covers Remote Access Service (RAS) API: dialing, connection
// enumeration, status retrieval, error string lookup, and hang-up.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static RASAPI32_SIGNATURES: &[HookSignature] = &[
    // ── RAS Dial ──────────────────────────────────────────────────────────
    HookSignature {
        module: "rasapi32.dll",
        function: "RasDialA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpRasDialExtensions", GuestPtr),
            ParamSpec::new("lpszPhonebook", PCStr),
            ParamSpec::new("lpRasDialParams", GuestPtr),
            ParamSpec::new("dwNotifierType", U32),
            ParamSpec::new("lpvNotifier", GuestPtr),
            ParamSpec::new("lphRasConn", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "rasapi32.dll",
        function: "RasDialW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpRasDialExtensions", GuestPtr),
            ParamSpec::new("lpszPhonebook", PCWStr),
            ParamSpec::new("lpRasDialParams", GuestPtr),
            ParamSpec::new("dwNotifierType", U32),
            ParamSpec::new("lpvNotifier", GuestPtr),
            ParamSpec::new("lphRasConn", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Connection Enumeration ────────────────────────────────────────────
    HookSignature {
        module: "rasapi32.dll",
        function: "RasEnumConnectionsA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpRasConn", GuestPtr),
            ParamSpec::new("lpcb", GuestPtr),
            ParamSpec::new("lpcConnections", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "rasapi32.dll",
        function: "RasEnumConnectionsW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpRasConn", GuestPtr),
            ParamSpec::new("lpcb", GuestPtr),
            ParamSpec::new("lpcConnections", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "rasapi32.dll",
        function: "RasEnumEntriesA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpReserved", GuestPtr),
            ParamSpec::new("lpszPhonebook", PCStr),
            ParamSpec::new("lpRasEntryName", GuestPtr),
            ParamSpec::new("lpcb", GuestPtr),
            ParamSpec::new("lpcEntries", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "rasapi32.dll",
        function: "RasEnumEntriesW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpReserved", GuestPtr),
            ParamSpec::new("lpszPhonebook", PCWStr),
            ParamSpec::new("lpRasEntryName", GuestPtr),
            ParamSpec::new("lpcb", GuestPtr),
            ParamSpec::new("lpcEntries", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Connection Status ─────────────────────────────────────────────────
    HookSignature {
        module: "rasapi32.dll",
        function: "RasGetConnectStatusA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hRasConn", Handle),
            ParamSpec::new("lpRasConnStatus", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "rasapi32.dll",
        function: "RasGetConnectStatusW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hRasConn", Handle),
            ParamSpec::new("lpRasConnStatus", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Error String ──────────────────────────────────────────────────────
    HookSignature {
        module: "rasapi32.dll",
        function: "RasGetErrorStringA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("uErrorValue", U32),
            ParamSpec::new("lpszErrorString", GuestPtr),
            ParamSpec::new("cBufSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "rasapi32.dll",
        function: "RasGetErrorStringW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("uErrorValue", U32),
            ParamSpec::new("lpszErrorString", GuestPtr),
            ParamSpec::new("cBufSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Hang Up ───────────────────────────────────────────────────────────
    HookSignature {
        module: "rasapi32.dll",
        function: "RasHangUpA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hRasConn", Handle)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "rasapi32.dll",
        function: "RasHangUpW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hRasConn", Handle)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
];
