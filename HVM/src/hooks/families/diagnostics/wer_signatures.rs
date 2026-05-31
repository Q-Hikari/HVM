//! Full `HookSignature` table for `wer.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static WER_SIGNATURES: &[HookSignature] = &[
    // ── WER Report lifecycle ───────────────────────────────────────────────
    HookSignature {
        module: "wer.dll",
        function: "WerReportCreate",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pwzEventType", PCWStr),
            ParamSpec::new("repType", U32),
            ParamSpec::new(
                "pReportInformation",
                OpaqueStructPtr("WER_REPORT_INFORMATION"),
            ),
            ParamSpec::with_dir("phReportHandle", Handle, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerReportSetParameter",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hReportHandle", Handle),
            ParamSpec::new("dwparamID", U32),
            ParamSpec::new("pwzName", PCWStr),
            ParamSpec::new("pwzValue", PCWStr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerReportAddFile",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hReportHandle", Handle),
            ParamSpec::new("pwzFile", PCWStr),
            ParamSpec::new("repFileType", U32),
            ParamSpec::new("dwFileFlags", U32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerReportSetUIOption",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hReportHandle", Handle),
            ParamSpec::new("repUITypeID", U32),
            ParamSpec::new("pwzValue", PCWStr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerReportSubmit",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hReportHandle", Handle),
            ParamSpec::new("consent", U32),
            ParamSpec::new("dwFlags", U32),
            ParamSpec::with_dir("pSubmitResult", U32, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerReportAddDump",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hReportHandle", Handle),
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hThread", Handle),
            ParamSpec::new("dumpType", U32),
            ParamSpec::new(
                "pExceptionParam",
                OpaqueStructPtr("WER_EXCEPTION_INFORMATION"),
            ),
            ParamSpec::new(
                "pDumpCustomOptions",
                OpaqueStructPtr("WER_DUMP_CUSTOM_OPTIONS"),
            ),
            ParamSpec::new("dwFlags", U32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerReportCloseHandle",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hReportHandle", Handle)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── WER Store management ───────────────────────────────────────────────
    HookSignature {
        module: "wer.dll",
        function: "WerStoreOpen",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("repStoreType", U32),
            ParamSpec::with_dir("phStoreHandle", Handle, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerStoreClose",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hStoreHandle", Handle)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerStoreGetFirstReportKey",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hStoreHandle", Handle),
            ParamSpec::with_dir("ppszReportKey", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerStoreGetNextReportKey",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hStoreHandle", Handle),
            ParamSpec::with_dir("ppszReportKey", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerFreeString",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("psz", PCWStr)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerStorePurge",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerStoreGetReportCount",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hStoreHandle", Handle),
            ParamSpec::with_dir("pdwReportCount", U32, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "WerStoreGetSizeOnDisk",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hStoreHandle", Handle),
            ParamSpec::with_dir("pqwSizeInBytes", U64, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Wait Chain Traversal ───────────────────────────────────────────────
    HookSignature {
        module: "wer.dll",
        function: "OpenThreadWaitChainSession",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("Flags", U32),
            ParamSpec::new("callback", FunctionPtr),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "GetThreadWaitChain",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("WctHandle", Handle),
            ParamSpec::new("Context", GuestPtr),
            ParamSpec::new("Flags", U32),
            ParamSpec::new("ThreadId", U32),
            ParamSpec::with_dir("pNodeCount", U32, Out),
            ParamSpec::with_dir("pChainInfo", GuestPtr, Out),
            ParamSpec::with_dir("pIsCycle", Bool32, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "CloseThreadWaitChainSession",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("WctHandle", Handle)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "wer.dll",
        function: "RegisterWaitChainCOMCallback",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("CallStateCallback", FunctionPtr),
            ParamSpec::new("ActivationStateCallback", FunctionPtr),
        ],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
];
