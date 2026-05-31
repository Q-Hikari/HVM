//! Full `HookSignature` table for `vcruntime140.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType::*};

pub(super) static VCRUNTIME140_SIGNATURES: &[HookSignature] = &[
    // ── Exception handling ────────────────────────────────────────────────
    HookSignature {
        module: "vcruntime140.dll",
        function: "__std_exception_copy",
        abi: LogicalAbi::Cdecl,
        params: &[
            ParamSpec::new("src", GuestPtr),
            ParamSpec::new("dst", GuestPtr),
        ],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "vcruntime140.dll",
        function: "__std_exception_destroy",
        abi: LogicalAbi::Cdecl,
        params: &[ParamSpec::new("exception", GuestPtr)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "vcruntime140.dll",
        function: "__std_terminate",
        abi: LogicalAbi::Cdecl,
        params: &[],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "vcruntime140.dll",
        function: "__std_type_info_destroy_list",
        abi: LogicalAbi::Cdecl,
        params: &[ParamSpec::new("typeInfoList", GuestPtr)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "vcruntime140.dll",
        function: "_purecall",
        abi: LogicalAbi::Cdecl,
        params: &[],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    // ── Memory / string ───────────────────────────────────────────────────
    HookSignature {
        module: "vcruntime140.dll",
        function: "memchr",
        abi: LogicalAbi::Cdecl,
        params: &[
            ParamSpec::new("ptr", GuestPtr),
            ParamSpec::new("c", I32),
            ParamSpec::new("count", SizeT),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "vcruntime140.dll",
        function: "memcpy",
        abi: LogicalAbi::Cdecl,
        params: &[
            ParamSpec::new("dest", GuestPtr),
            ParamSpec::new("src", GuestPtr),
            ParamSpec::new("count", SizeT),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
];
