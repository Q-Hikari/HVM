//! Full `HookSignature` table for `msimg32.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static MSIMG32_SIGNATURES: &[HookSignature] = &[
    // ── Alpha Blending ────────────────────────────────────────────────────
    HookSignature {
        module: "msimg32.dll",
        function: "AlphaBlend",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hdcDest", Handle),
            ParamSpec::new("xDest", I32),
            ParamSpec::new("yDest", I32),
            ParamSpec::new("wDest", I32),
            ParamSpec::new("hDest", I32),
            ParamSpec::new("hdcSrc", Handle),
            ParamSpec::new("xSrc", I32),
            ParamSpec::new("ySrc", I32),
            ParamSpec::new("wSrc", I32),
            ParamSpec::new("hSrc", I32),
            ParamSpec::new("blendFunction", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Transparent Blitting ──────────────────────────────────────────────
    HookSignature {
        module: "msimg32.dll",
        function: "TransparentBlt",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hdcDest", Handle),
            ParamSpec::new("xDest", I32),
            ParamSpec::new("yDest", I32),
            ParamSpec::new("wDest", I32),
            ParamSpec::new("hDest", I32),
            ParamSpec::new("hdcSrc", Handle),
            ParamSpec::new("xSrc", I32),
            ParamSpec::new("ySrc", I32),
            ParamSpec::new("wSrc", I32),
            ParamSpec::new("hSrc", I32),
            ParamSpec::new("crTransparent", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
];
