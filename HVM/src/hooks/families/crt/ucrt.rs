use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS_API_MS_WIN_CRT_RUNTIME_L1_1_0_DLL: &[(&str, LogicalAbi)] = &[
    ("_configure_narrow_argv", LogicalAbi::Cdecl),
    ("_configure_wide_argv", LogicalAbi::Cdecl),
];

static FUNCTIONS_API_MS_WIN_CRT_STRING_L1_1_0_DLL: &[(&str, LogicalAbi)] = &[
    ("isalnum", LogicalAbi::Cdecl),
    ("isalpha", LogicalAbi::Cdecl),
    ("isspace", LogicalAbi::Cdecl),
    ("strncat_s", LogicalAbi::Cdecl),
    ("strncpy", LogicalAbi::Cdecl),
    ("strncpy_s", LogicalAbi::Cdecl),
    ("tolower", LogicalAbi::Cdecl),
    ("wcsncat_s", LogicalAbi::Cdecl),
    ("wcsncpy_s", LogicalAbi::Cdecl),
];

static FUNCTIONS_API_MS_WIN_CRT_FILESYSTEM_L1_1_0_DLL: &[(&str, LogicalAbi)] =
    &[("_wchmod", LogicalAbi::Cdecl)];

static FUNCTIONS_API_MS_WIN_CRT_MATH_L1_1_0_DLL: &[(&str, LogicalAbi)] =
    &[("pow", LogicalAbi::Cdecl)];

static FUNCTIONS_API_MS_WIN_CRT_TIME_L1_1_0_DLL: &[(&str, LogicalAbi)] = &[
    ("_gmtime64_s", LogicalAbi::Cdecl),
    ("_localtime64_s", LogicalAbi::Cdecl),
];

static FUNCTIONS_API_MS_WIN_CRT_STDIO_L1_1_0_DLL: &[(&str, LogicalAbi)] = &[
    ("_set_fmode", LogicalAbi::Cdecl),
    ("__stdio_common_vsnprintf_s", LogicalAbi::Cdecl),
    ("__stdio_common_vsnwprintf_s", LogicalAbi::Cdecl),
    ("__stdio_common_vsscanf", LogicalAbi::Cdecl),
    ("fclose", LogicalAbi::Cdecl),
    ("fopen", LogicalAbi::Cdecl),
    ("fread", LogicalAbi::Cdecl),
    ("fseek", LogicalAbi::Cdecl),
    ("ftell", LogicalAbi::Cdecl),
];

pub fn register_ucrt_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs(
        "api-ms-win-crt-runtime-l1-1-0.dll",
        &FUNCTIONS_API_MS_WIN_CRT_RUNTIME_L1_1_0_DLL,
    );
    registry.register_function_stubs(
        "api-ms-win-crt-string-l1-1-0.dll",
        &FUNCTIONS_API_MS_WIN_CRT_STRING_L1_1_0_DLL,
    );
    registry.register_function_stubs(
        "api-ms-win-crt-filesystem-l1-1-0.dll",
        &FUNCTIONS_API_MS_WIN_CRT_FILESYSTEM_L1_1_0_DLL,
    );
    registry.register_function_stubs(
        "api-ms-win-crt-math-l1-1-0.dll",
        &FUNCTIONS_API_MS_WIN_CRT_MATH_L1_1_0_DLL,
    );
    registry.register_function_stubs(
        "api-ms-win-crt-time-l1-1-0.dll",
        &FUNCTIONS_API_MS_WIN_CRT_TIME_L1_1_0_DLL,
    );
    registry.register_function_stubs(
        "api-ms-win-crt-stdio-l1-1-0.dll",
        &FUNCTIONS_API_MS_WIN_CRT_STDIO_L1_1_0_DLL,
    );
}
