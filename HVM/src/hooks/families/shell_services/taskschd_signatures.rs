//! Full `HookSignature` table for `taskschd.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static TASKSCHD_SIGNATURES: &[HookSignature] = &[
    // ── COM DLL entry points ─────────────────────────────────────────────
    HookSignature {
        module: "taskschd.dll",
        function: "DllCanUnloadNow",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "taskschd.dll",
        function: "DllGetClassObject",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("rclsid", GuidPtr),
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::new("ppv", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "taskschd.dll",
        function: "DllRegisterServer",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "taskschd.dll",
        function: "DllUnregisterServer",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "taskschd.dll",
        function: "DllInstall",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("bInstall", Bool32),
            ParamSpec::new("pszCmdLine", PCWStr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
];
