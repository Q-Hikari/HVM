//! Full `HookSignature` table for `dbgcore.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static DBGCORE_SIGNATURES: &[HookSignature] = &[
    // ── Minidump generation and reading ────────────────────────────────────
    HookSignature {
        module: "dbgcore.dll",
        function: "MiniDumpWriteDump",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("ProcessId", U32),
            ParamSpec::new("hFile", Handle),
            ParamSpec::new("DumpType", U32),
            ParamSpec::new(
                "ExceptionParam",
                OpaqueStructPtr("MINIDUMP_EXCEPTION_INFORMATION"),
            ),
            ParamSpec::new(
                "UserStreamParam",
                OpaqueStructPtr("MINIDUMP_USER_STREAM_INFORMATION"),
            ),
            ParamSpec::new(
                "CallbackParam",
                OpaqueStructPtr("MINIDUMP_CALLBACK_INFORMATION"),
            ),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dbgcore.dll",
        function: "MiniDumpReadDumpStream",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("BaseOfDump", GuestPtr),
            ParamSpec::new("StreamNumber", U32),
            ParamSpec::with_dir("Dir", GuestPtr, Out),
            ParamSpec::with_dir("StreamPointer", GuestPtr, Out),
            ParamSpec::with_dir("StreamSize", U32, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
];
