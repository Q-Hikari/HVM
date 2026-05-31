//! Full `HookSignature` table for `combase.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static COMBASE_SIGNATURES: &[HookSignature] = &[
    // ── COM Initialization ────────────────────────────────────────────────
    HookSignature {
        module: "combase.dll",
        function: "CoInitializeEx",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pvReserved", GuestPtr),
            ParamSpec::new("dwCoInit", U32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "CoUninitialize",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    // ── GUID helpers ──────────────────────────────────────────────────────
    HookSignature {
        module: "combase.dll",
        function: "CoCreateGuid",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pguid", GuidPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "StringFromGUID2",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("rguid", GuidPtr),
            ParamSpec::new("lpszw", PWStr),
            ParamSpec::new("cchMax", I32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "IIDFromString",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpsz", PCWStr),
            ParamSpec::new("lpiid", GuidPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "CLSIDFromString",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpsz", PCWStr),
            ParamSpec::new("pclsid", GuidPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "StringFromIID",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::new("lplpsz", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "StringFromCLSID",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("rclsid", GuidPtr),
            ParamSpec::new("lplpsz", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── COM Memory Allocation ─────────────────────────────────────────────
    HookSignature {
        module: "combase.dll",
        function: "CoTaskMemAlloc",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("cb", SizeT)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "CoTaskMemFree",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pv", GuestPtr)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "CoTaskMemRealloc",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pv", GuestPtr), ParamSpec::new("cb", SizeT)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ── MTA Usage ─────────────────────────────────────────────────────────
    HookSignature {
        module: "combase.dll",
        function: "CoIncrementMTAUsage",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pCookie", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "CoDecrementMTAUsage",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pCookie", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── WinRT String Helpers ──────────────────────────────────────────────
    HookSignature {
        module: "combase.dll",
        function: "WindowsCreateString",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("sourceString", PCWStr),
            ParamSpec::new("length", U32),
            ParamSpec::new("hstring", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "WindowsDeleteString",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hstring", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "WindowsDuplicateString",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hstring", GuestPtr),
            ParamSpec::new("newHstring", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "WindowsGetStringLen",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hstring", GuestPtr)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "WindowsGetStringRawBuffer",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hstring", GuestPtr),
            ParamSpec::new("length", GuestPtr),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "WindowsIsStringEmpty",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hstring", GuestPtr)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── RoInitialize / RoUninitialize ─────────────────────────────────────
    HookSignature {
        module: "combase.dll",
        function: "RoInitialize",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("initType", U32)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "RoUninitialize",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "RoGetActivationFactory",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("activatableClassId", PCWStr),
            ParamSpec::new("iid", GuidPtr),
            ParamSpec::new("factory", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── COM Object Creation ───────────────────────────────────────────────
    HookSignature {
        module: "combase.dll",
        function: "CoCreateInstance",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("rclsid", GuidPtr),
            ParamSpec::new("pUnkOuter", GuestPtr),
            ParamSpec::new("dwClsCtx", U32),
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::new("ppv", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "CoGetClassObject",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("rclsid", GuidPtr),
            ParamSpec::new("dwClsCtx", U32),
            ParamSpec::new("pvReserved", GuestPtr),
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::new("ppv", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── PropVariant / IMalloc ─────────────────────────────────────────────
    HookSignature {
        module: "combase.dll",
        function: "PropVariantClear",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pvar", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "combase.dll",
        function: "CoGetMalloc",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwMemContext", U32),
            ParamSpec::new("ppMalloc", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
];
