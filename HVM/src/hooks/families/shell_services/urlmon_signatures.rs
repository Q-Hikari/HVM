//! Full `HookSignature` table for `urlmon.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static URLMON_SIGNATURES: &[HookSignature] = &[
    // ── URL Download helpers ─────────────────────────────────────────────
    HookSignature {
        module: "urlmon.dll",
        function: "URLDownloadToFileA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pCaller", GuestPtr),
            ParamSpec::new("szURL", PCStr),
            ParamSpec::new("szFileName", PCStr),
            ParamSpec::new("dwReserved", U32),
            ParamSpec::new("lpfnCB", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "urlmon.dll",
        function: "URLDownloadToFileW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pCaller", GuestPtr),
            ParamSpec::new("szURL", PCWStr),
            ParamSpec::new("szFileName", PCWStr),
            ParamSpec::new("dwReserved", U32),
            ParamSpec::new("lpfnCB", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "urlmon.dll",
        function: "URLDownloadToCacheFileA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pCaller", GuestPtr),
            ParamSpec::new("szURL", PCStr),
            ParamSpec::new("szFileName", PStr),
            ParamSpec::new("cchFileName", U32),
            ParamSpec::new("dwReserved", U32),
            ParamSpec::new("lpfnCB", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "urlmon.dll",
        function: "URLDownloadToCacheFileW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pCaller", GuestPtr),
            ParamSpec::new("szURL", PCWStr),
            ParamSpec::new("szFileName", PWStr),
            ParamSpec::new("cchFileName", U32),
            ParamSpec::new("dwReserved", U32),
            ParamSpec::new("lpfnCB", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Cache entry helpers ──────────────────────────────────────────────
    HookSignature {
        module: "urlmon.dll",
        function: "DeleteUrlCacheEntryA",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpszUrlName", PCStr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "urlmon.dll",
        function: "DeleteUrlCacheEntryW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpszUrlName", PCWStr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── User agent / feature control ─────────────────────────────────────
    HookSignature {
        module: "urlmon.dll",
        function: "ObtainUserAgentString",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwOption", U32),
            ParamSpec::new("pszUAOut", PStr),
            ParamSpec::new("cbSize", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "urlmon.dll",
        function: "CoInternetSetFeatureEnabled",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("FeatureEntry", U32),
            ParamSpec::new("dwFlags", U32),
            ParamSpec::new("fEnable", Bool32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── URI creation ─────────────────────────────────────────────────────
    HookSignature {
        module: "urlmon.dll",
        function: "CreateUri",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pwzURI", PCWStr),
            ParamSpec::new("dwFlags", U32),
            ParamSpec::new("dwReserved", U32),
            ParamSpec::new("ppURI", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
];
