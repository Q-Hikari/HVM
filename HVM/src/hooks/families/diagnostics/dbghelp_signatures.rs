//! Full `HookSignature` table for `dbghelp.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static DBGHELP_SIGNATURES: &[HookSignature] = &[
    // ── Symbol initialization / cleanup ────────────────────────────────────
    HookSignature {
        module: "dbghelp.dll",
        function: "SymInitialize",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("UserSearchPath", PCStr),
            ParamSpec::new("fInvadeProcess", Bool32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dbghelp.dll",
        function: "SymInitializeW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("UserSearchPath", PCWStr),
            ParamSpec::new("fInvadeProcess", Bool32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dbghelp.dll",
        function: "SymCleanup",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hProcess", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dbghelp.dll",
        function: "SymSetOptions",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("SymOptions", Hex32)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dbghelp.dll",
        function: "SymGetOptions",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Module loading ─────────────────────────────────────────────────────
    HookSignature {
        module: "dbghelp.dll",
        function: "SymLoadModuleEx",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hFile", Handle),
            ParamSpec::new("ImageName", PCStr),
            ParamSpec::new("ModuleName", PCStr),
            ParamSpec::new("BaseOfDll", U64),
            ParamSpec::new("DllSize", U32),
            ParamSpec::new("Data", GuestPtr),
            ParamSpec::new("Flags", U32),
        ],
        ret: ReturnSpec::U64,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dbghelp.dll",
        function: "SymLoadModuleExW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hFile", Handle),
            ParamSpec::new("ImageName", PCWStr),
            ParamSpec::new("ModuleName", PCWStr),
            ParamSpec::new("BaseOfDll", U64),
            ParamSpec::new("DllSize", U32),
            ParamSpec::new("Data", GuestPtr),
            ParamSpec::new("Flags", U32),
        ],
        ret: ReturnSpec::U64,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dbghelp.dll",
        function: "SymGetModuleBase64",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("dwAddr", U64),
        ],
        ret: ReturnSpec::U64,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dbghelp.dll",
        function: "SymFunctionTableAccess64",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("AddrBase", U64),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dbghelp.dll",
        function: "SymRefreshModuleList",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hProcess", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Symbol lookup ──────────────────────────────────────────────────────
    HookSignature {
        module: "dbghelp.dll",
        function: "SymFromAddr",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("Address", U64),
            ParamSpec::with_dir("Displacement", U64, Out),
            ParamSpec::new("Symbol", OpaqueStructPtr("SYMBOL_INFO")),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dbghelp.dll",
        function: "SymFromAddrW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("Address", U64),
            ParamSpec::with_dir("Displacement", U64, Out),
            ParamSpec::new("Symbol", OpaqueStructPtr("SYMBOL_INFOW")),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dbghelp.dll",
        function: "SymGetLineFromAddr64",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("dwAddr", U64),
            ParamSpec::with_dir("pdwDisplacement", U32, Out),
            ParamSpec::with_dir("Line", OpaqueStructPtr("IMAGEHLP_LINE64"), Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Name undecoration ──────────────────────────────────────────────────
    HookSignature {
        module: "dbghelp.dll",
        function: "UnDecorateSymbolName",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("name", PCStr),
            ParamSpec::with_dir("outputString", PStr, Out),
            ParamSpec::new("maxStringLength", U32),
            ParamSpec::new("flags", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Minidump (dbghelp re-export) ───────────────────────────────────────
    HookSignature {
        module: "dbghelp.dll",
        function: "MiniDumpWriteDump",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("ProcessId", U32),
            ParamSpec::new("hFile", Handle),
            ParamSpec::new("DumpType", U32),
            ParamSpec::new(
                "ExceptionParam",
                OpaqueStructPtr("MINIDUMP_EXCEPTION_INFORMATION"),
            ),
            ParamSpec::new(
                "UserStreamParam",
                OpaqueStructPtr("MINIDUMP_USER_STREAM_INFORMATION"),
            ),
            ParamSpec::new(
                "CallbackParam",
                OpaqueStructPtr("MINIDUMP_CALLBACK_INFORMATION"),
            ),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Stack walking ──────────────────────────────────────────────────────
    HookSignature {
        module: "dbghelp.dll",
        function: "StackWalk64",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("MachineType", U32),
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("hThread", Handle),
            ParamSpec::new("StackFrame", OpaqueStructPtr("STACKFRAME64")),
            ParamSpec::new("ContextRecord", GuestPtr),
            ParamSpec::new("ReadMemoryRoutine", FunctionPtr),
            ParamSpec::new("FunctionTableAccessRoutine", FunctionPtr),
            ParamSpec::new("GetModuleBaseRoutine", FunctionPtr),
            ParamSpec::new("TranslateAddressRoutine", FunctionPtr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
];
