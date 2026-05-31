//! Full `HookSignature` table for eventing API-set functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{
    HookFlags, LogicalAbi, ParamDirection::*, ParamType::*, ParamTypeDiscriminant,
};

pub(super) static EVENTING_SIGNATURES: &[HookSignature] = &[
    // ── Event Access Control (controller) ─────────────────────────────────
    HookSignature {
        module: "api-ms-win-eventing-controller-l1-1-0.dll",
        function: "EventAccessQuery",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("Guid", GuidPtr),
            ParamSpec::with_dir("Buffer", GuestPtr, Out),
            ParamSpec::with_dir("BufferSize", GuestPtrTo(ParamTypeDiscriminant::U32), InOut),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "api-ms-win-eventing-controller-l1-1-0.dll",
        function: "EventAccessRemove",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("Guid", GuidPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "api-ms-win-eventing-controller-l1-1-0.dll",
        function: "EventAccessControl",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("Guid", GuidPtr),
            ParamSpec::new("ulDescriptor", U32),
            ParamSpec::new("ulAction", U32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Trace Controller ──────────────────────────────────────────────────
    HookSignature {
        module: "api-ms-win-eventing-controller-l1-1-0.dll",
        function: "StartTraceW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir(
                "pTraceHandle",
                GuestPtrTo(ParamTypeDiscriminant::Handle),
                Out,
            ),
            ParamSpec::new("InstanceName", PCWStr),
            ParamSpec::new("Properties", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "api-ms-win-eventing-controller-l1-1-0.dll",
        function: "ControlTraceW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("TraceHandle", Handle),
            ParamSpec::new("InstanceName", PCWStr),
            ParamSpec::new("Properties", GuestPtr),
            ParamSpec::new("ControlCode", U32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "api-ms-win-eventing-controller-l1-1-0.dll",
        function: "StopTraceW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("TraceHandle", Handle),
            ParamSpec::new("InstanceName", PCWStr),
            ParamSpec::new("Properties", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "api-ms-win-eventing-controller-l1-1-0.dll",
        function: "QueryAllTracesW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("PropertyArray", GuestPtr, Out),
            ParamSpec::new("PropertyArrayCount", U32),
            ParamSpec::with_dir("LoggerCount", GuestPtrTo(ParamTypeDiscriminant::U32), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "api-ms-win-eventing-controller-l1-1-0.dll",
        function: "TraceSetInformation",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("TraceHandle", Handle),
            ParamSpec::new("InformationClass", U32),
            ParamSpec::new("TraceInformation", GuestPtr),
            ParamSpec::new("InformationLength", U32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "api-ms-win-eventing-controller-l1-1-0.dll",
        function: "EnableTraceEx2",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("TraceHandle", Handle),
            ParamSpec::new("ProviderId", GuidPtr),
            ParamSpec::new("ControlCode", U32),
            ParamSpec::new("Level", U32),
            ParamSpec::new("MatchAnyKeyword", U64),
            ParamSpec::new("MatchAllKeyword", U64),
            ParamSpec::new("Timeout", U32),
            ParamSpec::new("EnableParameters", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "api-ms-win-eventing-controller-l1-1-0.dll",
        function: "EnumerateTraceGuidsEx",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("TraceQueryInformationClass", U32),
            ParamSpec::new("InBuffer", GuestPtr),
            ParamSpec::new("InBufferSize", U32),
            ParamSpec::with_dir("OutBuffer", GuestPtr, Out),
            ParamSpec::new("OutBufferSize", U32),
            ParamSpec::with_dir("ReturnLength", GuestPtrTo(ParamTypeDiscriminant::U32), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Trace Consumer ────────────────────────────────────────────────────
    HookSignature {
        module: "api-ms-win-eventing-consumer-l1-1-0.dll",
        function: "OpenTraceA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("Logfile", GuestPtr)],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "api-ms-win-eventing-consumer-l1-1-0.dll",
        function: "OpenTraceW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("Logfile", GuestPtr)],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "api-ms-win-eventing-consumer-l1-1-0.dll",
        function: "ProcessTrace",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("HandleArray", GuestPtr),
            ParamSpec::new("HandleCount", U32),
            ParamSpec::new("StartTime", FileTimePtr),
            ParamSpec::new("EndTime", FileTimePtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "api-ms-win-eventing-consumer-l1-1-0.dll",
        function: "CloseTrace",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("TraceHandle", Handle)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
];
