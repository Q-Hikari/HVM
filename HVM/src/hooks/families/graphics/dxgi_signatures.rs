//! Full `HookSignature` table for `dxgi.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static DXGI_SIGNATURES: &[HookSignature] = &[
    // ── Factory Creation ──────────────────────────────────────────────────
    HookSignature {
        module: "dxgi.dll",
        function: "CreateDXGIFactory",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::with_dir("ppFactory", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dxgi.dll",
        function: "CreateDXGIFactory1",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::with_dir("ppFactory", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dxgi.dll",
        function: "CreateDXGIFactory2",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("Flags", U32),
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::with_dir("ppFactory", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Synthetic vtable method stubs ─────────────────────────────────────
    HookSignature {
        module: "dxgi.dll",
        function: "__vm_dxgi_factory_EnumAdapters",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("Adapter", U32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dxgi.dll",
        function: "__vm_dxgi_factory_MakeWindowAssociation",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("WindowHandle", Handle),
            ParamSpec::new("Flags", U32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "dxgi.dll",
        function: "__vm_dxgi_factory_Stub",
        abi: LogicalAbi::ComMethod,
        params: &[ParamSpec::new("this", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
];
