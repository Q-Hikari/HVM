//! Full `HookSignature` table for `winspool.drv` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType, ParamType::*};

pub(super) static WINSPOOL_DRV_SIGNATURES: &[HookSignature] = &[
    // ── Printer Handle Management ─────────────────────────────────────────
    HookSignature {
        module: "winspool.drv",
        function: "OpenPrinterA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pPrinterName", PCStr),
            ParamSpec::with_dir("phPrinter", GuestPtr, Out),
            ParamSpec::new("pDefault", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winspool.drv",
        function: "OpenPrinterW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pPrinterName", PCWStr),
            ParamSpec::with_dir("phPrinter", GuestPtr, Out),
            ParamSpec::new("pDefault", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winspool.drv",
        function: "ClosePrinter",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hPrinter", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Default Printer ───────────────────────────────────────────────────
    HookSignature {
        module: "winspool.drv",
        function: "GetDefaultPrinterA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszBuffer", PStr),
            ParamSpec::new(
                "pcchBuffer",
                ParamType::GuestPtrTo(crate::hooks::types::ParamTypeDiscriminant::U32),
            ),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winspool.drv",
        function: "GetDefaultPrinterW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszBuffer", PWStr),
            ParamSpec::new(
                "pcchBuffer",
                ParamType::GuestPtrTo(crate::hooks::types::ParamTypeDiscriminant::U32),
            ),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Document Spooling ─────────────────────────────────────────────────
    HookSignature {
        module: "winspool.drv",
        function: "StartDocPrinterA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hPrinter", Handle),
            ParamSpec::new("Level", U32),
            ParamSpec::new("pDocInfo", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winspool.drv",
        function: "StartDocPrinterW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hPrinter", Handle),
            ParamSpec::new("Level", U32),
            ParamSpec::new("pDocInfo", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winspool.drv",
        function: "EndDocPrinter",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hPrinter", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winspool.drv",
        function: "AbortPrinter",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hPrinter", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Page Management ───────────────────────────────────────────────────
    HookSignature {
        module: "winspool.drv",
        function: "StartPagePrinter",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hPrinter", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winspool.drv",
        function: "EndPagePrinter",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hPrinter", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Data Writing ──────────────────────────────────────────────────────
    HookSignature {
        module: "winspool.drv",
        function: "WritePrinter",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hPrinter", Handle),
            ParamSpec::new("pBuf", GuestPtr),
            ParamSpec::new("cbBuf", U32),
            ParamSpec::with_dir("pcWritten", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Printer Enumeration ───────────────────────────────────────────────
    HookSignature {
        module: "winspool.drv",
        function: "EnumPrintersA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("Flags", U32),
            ParamSpec::new("Name", PCStr),
            ParamSpec::new("Level", U32),
            ParamSpec::new("pPrinterEnum", GuestPtr),
            ParamSpec::new("cbBuf", U32),
            ParamSpec::with_dir("pcbNeeded", GuestPtr, Out),
            ParamSpec::with_dir("pcReturned", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "winspool.drv",
        function: "EnumPrintersW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("Flags", U32),
            ParamSpec::new("Name", PCWStr),
            ParamSpec::new("Level", U32),
            ParamSpec::new("pPrinterEnum", GuestPtr),
            ParamSpec::new("cbBuf", U32),
            ParamSpec::with_dir("pcbNeeded", GuestPtr, Out),
            ParamSpec::with_dir("pcReturned", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Document Properties ───────────────────────────────────────────────
    HookSignature {
        module: "winspool.drv",
        function: "DocumentPropertiesW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("hPrinter", Handle),
            ParamSpec::new("pDeviceName", PCWStr),
            ParamSpec::new("pDevModeOutput", GuestPtr),
            ParamSpec::new("pDevModeInput", GuestPtr),
            ParamSpec::new("fMode", U32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
];
