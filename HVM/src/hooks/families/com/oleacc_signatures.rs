//! Full `HookSignature` table for `oleacc.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static OLEACC_SIGNATURES: &[HookSignature] = &[
    HookSignature {
        module: "oleacc.dll",
        function: "AccessibleObjectFromWindow",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hwnd", Handle),
            ParamSpec::new("dwId", U32),
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::with_dir("ppvObject", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleacc.dll",
        function: "CreateStdAccessibleObject",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hwnd", Handle),
            ParamSpec::new("idObject", I32),
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::with_dir("ppvObject", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "oleacc.dll",
        function: "LresultFromObject",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::new("wParam", PointerSizedUInt),
            ParamSpec::new("pacc", GuestPtr),
        ],
        ret: ReturnSpec::PointerSizedUInt,
        flags: HookFlags::empty(),
    },
];
