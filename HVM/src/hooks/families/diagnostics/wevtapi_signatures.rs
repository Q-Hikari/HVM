//! Full `HookSignature` table for `wevtapi.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static WEVTAPI_SIGNATURES: &[HookSignature] = &[
    // ── Windows Event Log (EVTX) session ───────────────────────────────────
    HookSignature {
        module: "wevtapi.dll",
        function: "EvtOpenSession",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("LoginClass", U32),
            ParamSpec::new("Login", GuestPtr),
            ParamSpec::new("Timeout", U32),
            ParamSpec::new("Flags", U32),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    // ── Event query ────────────────────────────────────────────────────────
    HookSignature {
        module: "wevtapi.dll",
        function: "EvtQuery",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("Session", Handle),
            ParamSpec::new("Path", PCWStr),
            ParamSpec::new("Query", PCWStr),
            ParamSpec::new("Flags", U32),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    // ── Rendering ──────────────────────────────────────────────────────────
    HookSignature {
        module: "wevtapi.dll",
        function: "EvtCreateRenderContext",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("ValuePathsCount", U32),
            ParamSpec::new("ValuePaths", GuestPtr),
            ParamSpec::new("Flags", U32),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wevtapi.dll",
        function: "EvtNext",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("ResultSet", Handle),
            ParamSpec::new("EventArraySize", U32),
            ParamSpec::new("EventArray", GuestPtr),
            ParamSpec::new("Timeout", U32),
            ParamSpec::new("Flags", U32),
            ParamSpec::with_dir("Returned", U32, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wevtapi.dll",
        function: "EvtRender",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("Context", Handle),
            ParamSpec::new("Fragment", Handle),
            ParamSpec::new("Flags", U32),
            ParamSpec::new("BufferSize", U32),
            ParamSpec::new("Buffer", OutBuffer { len_param: 3 }),
            ParamSpec::with_dir("BufferUsed", U32, Out),
            ParamSpec::with_dir("PropertyCount", U32, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wevtapi.dll",
        function: "EvtFormatMessage",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("PublisherMetadata", Handle),
            ParamSpec::new("Event", Handle),
            ParamSpec::new("MessageId", U32),
            ParamSpec::new("ValueCount", U32),
            ParamSpec::new("Values", GuestPtr),
            ParamSpec::new("Flags", U32),
            ParamSpec::new("BufferSize", U32),
            ParamSpec::new("Buffer", OutBuffer { len_param: 6 }),
            ParamSpec::with_dir("BufferUsed", U32, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Cleanup ────────────────────────────────────────────────────────────
    HookSignature {
        module: "wevtapi.dll",
        function: "EvtClose",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("Object", Handle)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
];
