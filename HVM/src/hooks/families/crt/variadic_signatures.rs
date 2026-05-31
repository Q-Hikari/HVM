//! HookSignature definitions for variadic CRT and Windows formatting functions.
//!
//! These signatures declare only the FIXED (non-variadic) prefix of parameters.
//! The `HookFlags::VARIADIC` flag signals to the frame capture layer that
//! additional arguments should be read beyond the declared parameter count.
//!
//! Per-DLL slices are provided for targeted registration.

use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamType, ParamType::*};

// ── user32.dll variadic ──────────────────────────────────────────────────

/// Variadic signatures for `user32.dll` functions.
pub static USER32_VARIADIC_SIGNATURES: &[HookSignature] = &[
    // wsprintfA(LPSTR lpOut, LPCSTR lpFmt, ...) -- variadic cdecl
    HookSignature {
        module: "user32.dll",
        function: "wsprintfA",
        abi: LogicalAbi::VariadicCdecl,
        params: &[
            ParamSpec::new("lpOut", PStr),
            ParamSpec::new("lpFmt", PCStr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::from_bits(HookFlags::VARIADIC),
    },
    // wsprintfW(LPWSTR lpOut, LPCWSTR lpFmt, ...) -- variadic cdecl
    HookSignature {
        module: "user32.dll",
        function: "wsprintfW",
        abi: LogicalAbi::VariadicCdecl,
        params: &[
            ParamSpec::new("lpOut", PWStr),
            ParamSpec::new("lpFmt", PCWStr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::from_bits(HookFlags::VARIADIC),
    },
];

// ── msvcrt.dll variadic ──────────────────────────────────────────────────

/// Variadic signatures for `msvcrt.dll` functions.
pub static MSVCRT_VARIADIC_SIGNATURES: &[HookSignature] = &[
    // printf(const char* format, ...) -- cdecl
    HookSignature {
        module: "msvcrt.dll",
        function: "printf",
        abi: LogicalAbi::Cdecl,
        params: &[ParamSpec::new("format", PCStr)],
        ret: ReturnSpec::I32,
        flags: HookFlags::from_bits(HookFlags::VARIADIC),
    },
    // wprintf(const wchar_t* format, ...) -- cdecl
    HookSignature {
        module: "msvcrt.dll",
        function: "wprintf",
        abi: LogicalAbi::Cdecl,
        params: &[ParamSpec::new("format", PCWStr)],
        ret: ReturnSpec::I32,
        flags: HookFlags::from_bits(HookFlags::VARIADIC),
    },
    // sprintf(char* buffer, const char* format, ...) -- cdecl
    HookSignature {
        module: "msvcrt.dll",
        function: "sprintf",
        abi: LogicalAbi::Cdecl,
        params: &[
            ParamSpec::new("buffer", PStr),
            ParamSpec::new("format", PCStr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::from_bits(HookFlags::VARIADIC),
    },
    // swprintf_s(wchar_t* buffer, size_t sizeOfBuffer, const wchar_t* format, ...) -- cdecl
    HookSignature {
        module: "msvcrt.dll",
        function: "swprintf_s",
        abi: LogicalAbi::Cdecl,
        params: &[
            ParamSpec::new("buffer", PWStr),
            ParamSpec::new("sizeOfBuffer", ParamType::SizeT),
            ParamSpec::new("format", PCWStr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::from_bits(HookFlags::VARIADIC),
    },
    // sscanf(const char* buffer, const char* format, ...) -- cdecl
    HookSignature {
        module: "msvcrt.dll",
        function: "sscanf",
        abi: LogicalAbi::Cdecl,
        params: &[
            ParamSpec::new("buffer", PCStr),
            ParamSpec::new("format", PCStr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::from_bits(HookFlags::VARIADIC),
    },
    // _vsnwprintf(wchar_t* buffer, size_t count, const wchar_t* format, va_list argptr) -- cdecl
    HookSignature {
        module: "msvcrt.dll",
        function: "_vsnwprintf",
        abi: LogicalAbi::Cdecl,
        params: &[
            ParamSpec::new("buffer", PWStr),
            ParamSpec::new("count", ParamType::SizeT),
            ParamSpec::new("format", PCWStr),
            ParamSpec::new("argptr", ParamType::GuestPtr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::from_bits(HookFlags::VARIADIC),
    },
    // vsprintf(char* buffer, const char* format, va_list argptr) -- cdecl
    HookSignature {
        module: "msvcrt.dll",
        function: "vsprintf",
        abi: LogicalAbi::Cdecl,
        params: &[
            ParamSpec::new("buffer", PStr),
            ParamSpec::new("format", PCStr),
            ParamSpec::new("argptr", ParamType::GuestPtr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // _vsnprintf(char* buffer, size_t count, const char* format, va_list argptr) -- cdecl
    HookSignature {
        module: "msvcrt.dll",
        function: "_vsnprintf",
        abi: LogicalAbi::Cdecl,
        params: &[
            ParamSpec::new("buffer", PStr),
            ParamSpec::new("count", ParamType::SizeT),
            ParamSpec::new("format", PCStr),
            ParamSpec::new("argptr", ParamType::GuestPtr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
];

// ── kernel32.dll ─────────────────────────────────────────────────────────

/// Variadic signatures for `kernel32.dll` functions.
///
/// Note: FormatMessage is NOT variadic in the classic sense -- it takes
/// va_list via the Arguments parameter.  We flag it VARIADIC so the capture
/// layer can record extra stack space for diagnostics.
pub static KERNEL32_VARIADIC_SIGNATURES: &[HookSignature] = &[
    // FormatMessageW(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId,
    //                DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize,
    //                va_list* Arguments) -- WinApi
    HookSignature {
        module: "kernel32.dll",
        function: "FormatMessageW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwFlags", ParamType::Hex32),
            ParamSpec::new("lpSource", ParamType::GuestPtr),
            ParamSpec::new("dwMessageId", ParamType::U32),
            ParamSpec::new("dwLanguageId", ParamType::U32),
            ParamSpec::new("lpBuffer", PWStr),
            ParamSpec::new("nSize", ParamType::U32),
            ParamSpec::new("Arguments", ParamType::GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::from_bits(HookFlags::VARIADIC),
    },
];
