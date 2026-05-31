//! Full `HookSignature` table for `comdlg32.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static COMDLG32_SIGNATURES: &[HookSignature] = &[
    // ── Extended Error ────────────────────────────────────────────────────
    HookSignature {
        module: "comdlg32.dll",
        function: "CommDlgExtendedError",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── File Dialogs (ANSI) ───────────────────────────────────────────────
    HookSignature {
        module: "comdlg32.dll",
        function: "GetOpenFileNameA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpofn", OpaqueStructPtr("OPENFILENAMEA"))],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comdlg32.dll",
        function: "GetSaveFileNameA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpofn", OpaqueStructPtr("OPENFILENAMEA"))],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comdlg32.dll",
        function: "GetFileTitleA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpszFile", PCStr),
            ParamSpec::new("lpszTitle", PStr),
            ParamSpec::new("cbBuf", U16),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // ── File Dialogs (Wide) ───────────────────────────────────────────────
    HookSignature {
        module: "comdlg32.dll",
        function: "GetOpenFileNameW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpofn", OpaqueStructPtr("OPENFILENAMEW"))],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comdlg32.dll",
        function: "GetSaveFileNameW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpofn", OpaqueStructPtr("OPENFILENAMEW"))],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comdlg32.dll",
        function: "GetFileTitleW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpszFile", PCWStr),
            ParamSpec::new("lpszTitle", PWStr),
            ParamSpec::new("cbBuf", U16),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // ── Color Dialog ──────────────────────────────────────────────────────
    HookSignature {
        module: "comdlg32.dll",
        function: "ChooseColorA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpcc", OpaqueStructPtr("CHOOSECOLORA"))],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comdlg32.dll",
        function: "ChooseColorW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpcc", OpaqueStructPtr("CHOOSECOLORW"))],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Font Dialog ───────────────────────────────────────────────────────
    HookSignature {
        module: "comdlg32.dll",
        function: "ChooseFontA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpcf", OpaqueStructPtr("CHOOSEFONTA"))],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comdlg32.dll",
        function: "ChooseFontW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpcf", OpaqueStructPtr("CHOOSEFONTW"))],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Print Dialog ──────────────────────────────────────────────────────
    HookSignature {
        module: "comdlg32.dll",
        function: "PrintDlgA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lppd", OpaqueStructPtr("PRINTDLGA"))],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comdlg32.dll",
        function: "PrintDlgW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lppd", OpaqueStructPtr("PRINTDLGW"))],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Page Setup Dialog ─────────────────────────────────────────────────
    HookSignature {
        module: "comdlg32.dll",
        function: "PageSetupDlgA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lppsd", OpaqueStructPtr("PAGESETUPDLGA"))],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comdlg32.dll",
        function: "PageSetupDlgW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lppsd", OpaqueStructPtr("PAGESETUPDLGW"))],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Find/Replace Dialog ───────────────────────────────────────────────
    HookSignature {
        module: "comdlg32.dll",
        function: "FindTextA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpfr", OpaqueStructPtr("FINDREPLACEA"))],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comdlg32.dll",
        function: "FindTextW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpfr", OpaqueStructPtr("FINDREPLACEW"))],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comdlg32.dll",
        function: "ReplaceTextA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpfr", OpaqueStructPtr("FINDREPLACEA"))],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comdlg32.dll",
        function: "ReplaceTextW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpfr", OpaqueStructPtr("FINDREPLACEW"))],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
];
