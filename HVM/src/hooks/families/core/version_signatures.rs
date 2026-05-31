//! Full `HookSignature` table for `version.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static VERSION_SIGNATURES: &[HookSignature] = &[
    // ── File Version Info Size ────────────────────────────────────────────
    HookSignature {
        module: "version.dll",
        function: "GetFileVersionInfoSizeA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lptstrFilename", PCStr),
            ParamSpec::with_dir("lpdwHandle", GuestPtr, Out),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "version.dll",
        function: "GetFileVersionInfoSizeW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lptstrFilename", PCWStr),
            ParamSpec::with_dir("lpdwHandle", GuestPtr, Out),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "version.dll",
        function: "GetFileVersionInfoSizeExA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwFlags", U32),
            ParamSpec::new("lptstrFilename", PCStr),
            ParamSpec::with_dir("lpdwHandle", GuestPtr, Out),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "version.dll",
        function: "GetFileVersionInfoSizeExW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwFlags", U32),
            ParamSpec::new("lptstrFilename", PCWStr),
            ParamSpec::with_dir("lpdwHandle", GuestPtr, Out),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Get File Version Info ─────────────────────────────────────────────
    HookSignature {
        module: "version.dll",
        function: "GetFileVersionInfoA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lptstrFilename", PCStr),
            ParamSpec::new("dwHandle", U32),
            ParamSpec::new("dwLen", U32),
            ParamSpec::new("lpData", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "version.dll",
        function: "GetFileVersionInfoW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lptstrFilename", PCWStr),
            ParamSpec::new("dwHandle", U32),
            ParamSpec::new("dwLen", U32),
            ParamSpec::new("lpData", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "version.dll",
        function: "GetFileVersionInfoExA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwFlags", U32),
            ParamSpec::new("lptstrFilename", PCStr),
            ParamSpec::new("dwHandle", U32),
            ParamSpec::new("dwLen", U32),
            ParamSpec::new("lpData", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "version.dll",
        function: "GetFileVersionInfoExW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwFlags", U32),
            ParamSpec::new("lptstrFilename", PCWStr),
            ParamSpec::new("dwHandle", U32),
            ParamSpec::new("dwLen", U32),
            ParamSpec::new("lpData", GuestPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── VerQueryValue ─────────────────────────────────────────────────────
    HookSignature {
        module: "version.dll",
        function: "VerQueryValueA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pBlock", GuestPtr),
            ParamSpec::new("lpSubBlock", PCStr),
            ParamSpec::with_dir("lplpBuffer", GuestPtr, Out),
            ParamSpec::with_dir("puLen", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "version.dll",
        function: "VerQueryValueW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pBlock", GuestPtr),
            ParamSpec::new("lpSubBlock", PCWStr),
            ParamSpec::with_dir("lplpBuffer", GuestPtr, Out),
            ParamSpec::with_dir("puLen", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── VerLanguageName ───────────────────────────────────────────────────
    HookSignature {
        module: "version.dll",
        function: "VerLanguageNameA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("wLang", U32),
            ParamSpec::new("szLang", PStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "version.dll",
        function: "VerLanguageNameW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("wLang", U32),
            ParamSpec::new("szLang", PWStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
];
