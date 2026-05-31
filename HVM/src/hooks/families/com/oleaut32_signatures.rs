//! Full `HookSignature` table for `oleaut32.dll` functions.
//!
//! Covers BSTR, VARIANT, SafeArray, type library, and ordinal exports.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static OLEAUT32_SIGNATURES: &[HookSignature] = &[
    // ── BSTR Allocation ───────────────────────────────────────────────────
    HookSignature {
        module: "oleaut32.dll",
        function: "SysAllocString",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("psz", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SysAllocStringLen",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("psz", GuestPtr), ParamSpec::new("cch", U32)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SysAllocStringByteLen",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("psz", GuestPtr), ParamSpec::new("cch", U32)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SysReAllocString",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pbstr", GuestPtr),
            ParamSpec::new("psz", GuestPtr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SysReAllocStringLen",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pbstr", GuestPtr),
            ParamSpec::new("psz", GuestPtr),
            ParamSpec::new("cch", U32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SysFreeString",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("bstr", GuestPtr)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SysStringLen",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("bstr", GuestPtr)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SysStringByteLen",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("bstr", GuestPtr)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── VARIANT Operations ────────────────────────────────────────────────
    HookSignature {
        module: "oleaut32.dll",
        function: "VariantInit",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pvarg", GuestPtr)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "VariantClear",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("pvarg", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "VariantCopy",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pvargDest", GuestPtr),
            ParamSpec::new("pvargSrc", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "VariantChangeType",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pvargDest", GuestPtr),
            ParamSpec::new("pvarSrc", GuestPtr),
            ParamSpec::new("wFlags", U16),
            ParamSpec::new("vt", U16),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Variant Conversion ────────────────────────────────────────────────
    HookSignature {
        module: "oleaut32.dll",
        function: "VarBstrFromDate",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("date", U64),
            ParamSpec::new("lcid", U32),
            ParamSpec::new("dwFlags", U32),
            ParamSpec::new("pbstrOut", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "VarUI4FromStr",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("strIn", GuestPtr),
            ParamSpec::new("lcid", U32),
            ParamSpec::new("dwFlags", U32),
            ParamSpec::new("pulOut", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── SafeArray ─────────────────────────────────────────────────────────
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayCreate",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("vt", U16),
            ParamSpec::new("cDims", U32),
            ParamSpec::new("rgsabound", GuestPtr),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayCreateVector",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("vt", U16),
            ParamSpec::new("lLbound", I32),
            ParamSpec::new("cElements", U32),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayDestroy",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("psa", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayGetDim",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("psa", GuestPtr)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayGetElemsize",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("psa", GuestPtr)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayAccessData",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("psa", GuestPtr),
            ParamSpec::new("ppvData", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayUnaccessData",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("psa", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayLock",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("psa", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayUnlock",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("psa", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayGetUBound",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("psa", GuestPtr),
            ParamSpec::new("nDim", U32),
            ParamSpec::new("plUbound", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayGetLBound",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("psa", GuestPtr),
            ParamSpec::new("nDim", U32),
            ParamSpec::new("plLbound", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayPutElement",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("psa", GuestPtr),
            ParamSpec::new("rgIndices", GuestPtr),
            ParamSpec::new("pv", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayGetElement",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("psa", GuestPtr),
            ParamSpec::new("rgIndices", GuestPtr),
            ParamSpec::new("pv", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SafeArrayPtrOfIndex",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("psa", GuestPtr),
            ParamSpec::new("rgIndices", GuestPtr),
            ParamSpec::new("ppv", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Type Library / Time Conversion ────────────────────────────────────
    HookSignature {
        module: "oleaut32.dll",
        function: "LoadTypeLib",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("szFile", GuestPtr),
            ParamSpec::new("pptlib", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "SystemTimeToVariantTime",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpSystemTime", GuestPtr),
            ParamSpec::new("pvtime", GuestPtr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "VariantTimeToSystemTime",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("vtime", U64),
            ParamSpec::new("lpSystemTime", GuestPtr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleaut32.dll",
        function: "OleCreateFontIndirect",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpFontDesc", GuestPtr),
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::new("lplpObj", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Ordinal exports ───────────────────────────────────────────────────
    // ordinal_2 = SysAllocString (1 param: BSTR*)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_2",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("p1", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ordinal_4 (2 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_4",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_6 (1 param)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_6",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("p1", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ordinal_7 (1 param)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_7",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("p1", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ordinal_8 (1 param)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_8",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("p1", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ordinal_9 (1 param)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_9",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("p1", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ordinal_10 (1 param)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_10",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("p1", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ordinal_11 (2 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_11",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_12 (4 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_12",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
            ParamSpec::new("p3", U32),
            ParamSpec::new("p4", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_15 (3 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_15",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
            ParamSpec::new("p3", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_16 (1 param)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_16",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("p1", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ordinal_17 (1 param)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_17",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("p1", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ordinal_18 (1 param)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_18",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("p1", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ordinal_19 (3 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_19",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
            ParamSpec::new("p3", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_20 (3 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_20",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
            ParamSpec::new("p3", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_21 (1 param)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_21",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("p1", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ordinal_22 (1 param)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_22",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("p1", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ordinal_23 (2 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_23",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_24 (1 param)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_24",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("p1", GuestPtr)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ordinal_25 (3 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_25",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
            ParamSpec::new("p3", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_26 (3 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_26",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
            ParamSpec::new("p3", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_27 (6 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_27",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
            ParamSpec::new("p3", GuestPtr),
            ParamSpec::new("p4", GuestPtr),
            ParamSpec::new("p5", GuestPtr),
            ParamSpec::new("p6", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_114 (4 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_114",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
            ParamSpec::new("p3", U32),
            ParamSpec::new("p4", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_148 (3 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_148",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
            ParamSpec::new("p3", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_149 (2 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_149",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_161 (2 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_161",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_184 (2 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_184",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_185 (2 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_185",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_192 (2 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_192",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_194 (4 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_194",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
            ParamSpec::new("p3", U32),
            ParamSpec::new("p4", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_220 (2 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_220",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_411 (4 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_411",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
            ParamSpec::new("p3", U32),
            ParamSpec::new("p4", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ordinal_420 (3 params)
    HookSignature {
        module: "oleaut32.dll",
        function: "ordinal_420",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("p1", GuestPtr),
            ParamSpec::new("p2", GuestPtr),
            ParamSpec::new("p3", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
];
