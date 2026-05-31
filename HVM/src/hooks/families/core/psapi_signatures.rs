//! Full `HookSignature` table for `psapi.dll` and its `K32*` kernel32 forwards.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static PSAPI_SIGNATURES: &[HookSignature] = &[
    // ── Process / Module Enumeration ──────────────────────────────────────
    HookSignature {
        module: "psapi.dll",
        function: "EnumProcesses",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpidProcess", OutBuffer { len_param: 1 }),
            ParamSpec::new("cb", U32),
            ParamSpec::with_dir("lpcbNeeded", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "psapi.dll",
        function: "EnumProcessModules",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("lphModule", OutBuffer { len_param: 2 }),
            ParamSpec::new("cb", U32),
            ParamSpec::with_dir("lpcbNeeded", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "psapi.dll",
        function: "EnumProcessModulesEx",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("lphModule", OutBuffer { len_param: 2 }),
            ParamSpec::new("cb", U32),
            ParamSpec::with_dir("lpcbNeeded", GuestPtr, Out),
            ParamSpec::new("dwFilterFlag", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "kernel32.dll",
        function: "K32EnumProcessModules",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("lphModule", OutBuffer { len_param: 2 }),
            ParamSpec::new("cb", U32),
            ParamSpec::with_dir("lpcbNeeded", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "kernel32.dll",
        function: "K32EnumProcessModulesEx",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("lphModule", OutBuffer { len_param: 2 }),
            ParamSpec::new("cb", U32),
            ParamSpec::with_dir("lpcbNeeded", GuestPtr, Out),
            ParamSpec::new("dwFilterFlag", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Module Name ───────────────────────────────────────────────────────
    HookSignature {
        module: "psapi.dll",
        function: "GetModuleBaseNameA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hModule", ModuleHandle),
            ParamSpec::new("lpBaseName", PStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "psapi.dll",
        function: "GetModuleBaseNameW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hModule", ModuleHandle),
            ParamSpec::new("lpBaseName", PWStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "kernel32.dll",
        function: "K32GetModuleBaseNameA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hModule", ModuleHandle),
            ParamSpec::new("lpBaseName", PStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "kernel32.dll",
        function: "K32GetModuleBaseNameW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hModule", ModuleHandle),
            ParamSpec::new("lpBaseName", PWStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Module File Name ──────────────────────────────────────────────────
    HookSignature {
        module: "psapi.dll",
        function: "GetModuleFileNameExA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hModule", ModuleHandle),
            ParamSpec::new("lpFilename", PStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "psapi.dll",
        function: "GetModuleFileNameExW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hModule", ModuleHandle),
            ParamSpec::new("lpFilename", PWStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "kernel32.dll",
        function: "K32GetModuleFileNameExA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hModule", ModuleHandle),
            ParamSpec::new("lpFilename", PStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "kernel32.dll",
        function: "K32GetModuleFileNameExW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hModule", ModuleHandle),
            ParamSpec::new("lpFilename", PWStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Module Information ────────────────────────────────────────────────
    HookSignature {
        module: "psapi.dll",
        function: "GetModuleInformation",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hModule", ModuleHandle),
            ParamSpec::new("lpmodinfo", GuestPtr),
            ParamSpec::new("cb", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "kernel32.dll",
        function: "K32GetModuleInformation",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hModule", ModuleHandle),
            ParamSpec::new("lpmodinfo", GuestPtr),
            ParamSpec::new("cb", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Process Image File Name ───────────────────────────────────────────
    HookSignature {
        module: "psapi.dll",
        function: "GetProcessImageFileNameA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("lpImageFileName", PStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "psapi.dll",
        function: "GetProcessImageFileNameW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("lpImageFileName", PWStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Mapped File Name ──────────────────────────────────────────────────
    HookSignature {
        module: "psapi.dll",
        function: "GetMappedFileNameA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("lpv", GuestPtr),
            ParamSpec::new("lpFilename", PStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "psapi.dll",
        function: "GetMappedFileNameW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("lpv", GuestPtr),
            ParamSpec::new("lpFilename", PWStr),
            ParamSpec::new("nSize", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Working Set ───────────────────────────────────────────────────────
    HookSignature {
        module: "psapi.dll",
        function: "EmptyWorkingSet",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hProcess", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Process Memory Info ───────────────────────────────────────────────
    HookSignature {
        module: "psapi.dll",
        function: "GetProcessMemoryInfo",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("ppsmemCounters", GuestPtr),
            ParamSpec::new("cb", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "kernel32.dll",
        function: "K32GetProcessMemoryInfo",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("ppsmemCounters", GuestPtr),
            ParamSpec::new("cb", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
];
