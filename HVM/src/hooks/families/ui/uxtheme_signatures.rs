//! Full `HookSignature` table for `uxtheme.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static UXHEME_SIGNATURES: &[HookSignature] = &[
    // ── Theme Data Management ─────────────────────────────────────────────
    HookSignature {
        module: "uxtheme.dll",
        function: "OpenThemeData",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("pszClassList", PCWStr),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "uxtheme.dll",
        function: "CloseThemeData",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hTheme", Handle)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "uxtheme.dll",
        function: "GetWindowTheme",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hWnd", Handle)],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    // ── Theme Drawing ─────────────────────────────────────────────────────
    HookSignature {
        module: "uxtheme.dll",
        function: "DrawThemeBackground",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hTheme", Handle),
            ParamSpec::new("hdc", Handle),
            ParamSpec::new("iPartId", I32),
            ParamSpec::new("iStateId", I32),
            ParamSpec::new("pRect", GuestPtr),
            ParamSpec::new("pClipRect", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "uxtheme.dll",
        function: "DrawThemeParentBackground",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("hdc", Handle),
            ParamSpec::new("prc", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "uxtheme.dll",
        function: "DrawThemeText",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hTheme", Handle),
            ParamSpec::new("hdc", Handle),
            ParamSpec::new("iPartId", I32),
            ParamSpec::new("iStateId", I32),
            ParamSpec::new("pszText", PCWStr),
            ParamSpec::new("iCharCount", I32),
            ParamSpec::new("dwTextFlags", U32),
            ParamSpec::new("dwTextFlags2", U32),
            ParamSpec::new("pRect", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Theme Information ──────────────────────────────────────────────────
    HookSignature {
        module: "uxtheme.dll",
        function: "GetCurrentThemeName",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszThemeFileName", PWStr),
            ParamSpec::new("dwMaxNameChars", I32),
            ParamSpec::new("pszColorBuff", PWStr),
            ParamSpec::new("cchMaxColorChars", I32),
            ParamSpec::new("pszSizeBuff", PWStr),
            ParamSpec::new("cchMaxSizeChars", I32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "uxtheme.dll",
        function: "GetThemeColor",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hTheme", Handle),
            ParamSpec::new("iPartId", I32),
            ParamSpec::new("iStateId", I32),
            ParamSpec::new("iPropId", I32),
            ParamSpec::new("pColor", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "uxtheme.dll",
        function: "GetThemePartSize",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hTheme", Handle),
            ParamSpec::new("hdc", Handle),
            ParamSpec::new("iPartId", I32),
            ParamSpec::new("iStateId", I32),
            ParamSpec::new("prc", GuestPtr),
            ParamSpec::new("eSize", I32),
            ParamSpec::new("psz", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "uxtheme.dll",
        function: "GetThemeSysColor",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hTheme", Handle),
            ParamSpec::new("iColorId", I32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // ── Theme Query ───────────────────────────────────────────────────────
    HookSignature {
        module: "uxtheme.dll",
        function: "IsAppThemed",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "uxtheme.dll",
        function: "IsThemeBackgroundPartiallyTransparent",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hTheme", Handle),
            ParamSpec::new("iPartId", I32),
            ParamSpec::new("iStateId", I32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
];
