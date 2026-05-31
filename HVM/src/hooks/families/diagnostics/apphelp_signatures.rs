//! Full `HookSignature` table for `apphelp.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static APPHELP_SIGNATURES: &[HookSignature] = &[
    // ── Application compatibility / shim database ───────────────────────────
    HookSignature {
        module: "apphelp.dll",
        function: "ApphelpCheckShellObject",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pObjectCLSID", GuidPtr),
            ParamSpec::new("bInstall", Bool32),
            ParamSpec::with_dir("pbIsApproved", U32, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "apphelp.dll",
        function: "SdbInitDatabase",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwFlags", U32),
            ParamSpec::new("pszDatabasePath", PCStr),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "apphelp.dll",
        function: "SdbOpenDatabase",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pszDatabasePath", PCStr),
            ParamSpec::new("dwOpenFlags", U32),
        ],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "apphelp.dll",
        function: "SdbOpenApphelpDetailsDatabase",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pszDatabasePath", PCStr)],
        ret: ReturnSpec::Handle,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "apphelp.dll",
        function: "SdbCloseDatabase",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hSDB", Handle)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "apphelp.dll",
        function: "SdbReleaseDatabase",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hSDB", Handle)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "apphelp.dll",
        function: "SdbGetAppPatchDir",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hSDB", Handle),
            ParamSpec::with_dir("szAppPatchDir", PStr, Out),
            ParamSpec::new("cchAppPatchDir", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "apphelp.dll",
        function: "SdbTagRefToTagID",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hSDB", Handle),
            ParamSpec::new("trWhich", U32),
            ParamSpec::with_dir("ptiWhich", GuestPtr, Out),
            ParamSpec::with_dir("ptiDefault", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "apphelp.dll",
        function: "ShimFlushCache",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pvReserved", GuestPtr),
            ParamSpec::new("pszDllName", PCStr),
            ParamSpec::new("pszHookExeName", PCStr),
            ParamSpec::new("pvReserved2", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
];
