//! Full `HookSignature` table for `gdiplus.dll` functions.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static GDIPLUS_SIGNATURES: &[HookSignature] = &[
    // ── Memory Management ─────────────────────────────────────────────────
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipAlloc",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("size", SizeT)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipFree",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("ptr", GuestPtr)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    // ── Startup / Shutdown ────────────────────────────────────────────────
    HookSignature {
        module: "gdiplus.dll",
        function: "GdiplusStartup",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("token", GuestPtr, Out),
            ParamSpec::new("input", GuestPtr),
            ParamSpec::new("output", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdiplusShutdown",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("token", PointerSizedUInt)],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    // ── Graphics Object ───────────────────────────────────────────────────
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipCreateFromHDC",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hdc", Handle),
            ParamSpec::with_dir("graphics", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipDeleteGraphics",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("graphics", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipGetImageGraphicsContext",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("image", GuestPtr),
            ParamSpec::with_dir("graphics", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Image Operations ──────────────────────────────────────────────────
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipCloneImage",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("image", GuestPtr),
            ParamSpec::with_dir("cloneImage", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipDisposeImage",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("image", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipGetImageHeight",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("image", GuestPtr),
            ParamSpec::with_dir("height", U32, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipGetImageWidth",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("image", GuestPtr),
            ParamSpec::with_dir("width", U32, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipGetImagePixelFormat",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("image", GuestPtr),
            ParamSpec::with_dir("format", I32, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipGetImagePalette",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("image", GuestPtr),
            ParamSpec::with_dir("palette", GuestPtr, Out),
            ParamSpec::new("size", I32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipGetImagePaletteSize",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("image", GuestPtr),
            ParamSpec::with_dir("size", I32, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Bitmap Creation ───────────────────────────────────────────────────
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipCreateBitmapFromHBITMAP",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hbm", Handle),
            ParamSpec::new("hpal", Handle),
            ParamSpec::with_dir("bitmap", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipCreateBitmapFromScan0",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("width", I32),
            ParamSpec::new("height", I32),
            ParamSpec::new("stride", I32),
            ParamSpec::new("format", I32),
            ParamSpec::new("scan0", GuestPtr),
            ParamSpec::with_dir("bitmap", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipCreateBitmapFromStream",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("stream", GuestPtr),
            ParamSpec::with_dir("bitmap", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Bitmap Lock/Unlock ────────────────────────────────────────────────
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipBitmapLockBits",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("bitmap", GuestPtr),
            ParamSpec::new("rect", GuestPtr),
            ParamSpec::new("flags", U32),
            ParamSpec::new("format", I32),
            ParamSpec::with_dir("lockedBitmapData", GuestPtr, Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipBitmapUnlockBits",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("bitmap", GuestPtr),
            ParamSpec::new("lockedBitmapData", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Drawing Operations ────────────────────────────────────────────────
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipDrawImageI",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("graphics", GuestPtr),
            ParamSpec::new("image", GuestPtr),
            ParamSpec::new("x", I32),
            ParamSpec::new("y", I32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipDrawImageRectI",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("graphics", GuestPtr),
            ParamSpec::new("image", GuestPtr),
            ParamSpec::new("x", I32),
            ParamSpec::new("y", I32),
            ParamSpec::new("width", I32),
            ParamSpec::new("height", I32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    // ── Interpolation Mode ────────────────────────────────────────────────
    HookSignature {
        module: "gdiplus.dll",
        function: "GdipSetInterpolationMode",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("graphics", GuestPtr),
            ParamSpec::new("interpolationMode", I32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
];
