//! Full `HookSignature` table for `comctl32.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static COMCTL32_SIGNATURES: &[HookSignature] = &[
    // ── Common Controls Initialization ────────────────────────────────────
    HookSignature {
        module: "comctl32.dll",
        function: "InitCommonControlsEx",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new(
            "lpInitCtrls",
            OpaqueStructPtr("INITCOMMONCONTROLSEX"),
        )],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── ImageList Functions ───────────────────────────────────────────────
    HookSignature {
        module: "comctl32.dll",
        function: "ImageList_Draw",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("himl", Handle),
            ParamSpec::new("i", I32),
            ParamSpec::new("hdcDst", Handle),
            ParamSpec::new("x", I32),
            ParamSpec::new("y", I32),
            ParamSpec::new("fStyle", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comctl32.dll",
        function: "ImageList_GetImageCount",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("himl", Handle)],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comctl32.dll",
        function: "ImageList_Remove",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("himl", Handle), ParamSpec::new("i", I32)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comctl32.dll",
        function: "ImageList_ReplaceIcon",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("himl", Handle),
            ParamSpec::new("i", I32),
            ParamSpec::new("hicon", Handle),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // ── Ordinal exports ───────────────────────────────────────────────────
    HookSignature {
        module: "comctl32.dll",
        function: "ordinal_345",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("arg1", GuestPtr)],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "comctl32.dll",
        function: "ordinal_381",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("arg1", GuestPtr),
            ParamSpec::new("arg2", GuestPtr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
];
