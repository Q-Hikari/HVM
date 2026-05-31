//! Windows and engine constants extracted from engine.rs for maintainability.

// DLL entry point reasons
pub const DLL_PROCESS_ATTACH: u64 = 1;
pub const DLL_PROCESS_DETACH: u64 = 0;
pub const DLL_THREAD_ATTACH: u64 = 2;
pub const DLL_THREAD_DETACH: u64 = 3;

// Pseudo handles
pub const PROCESS_HANDLE_PSEUDO: u64 = 0xFFFF_FFFF;
pub const INVALID_HANDLE_VALUE: u64 = u32::MAX as u64;

// Shell process space
pub const SHELL_PROCESS_SPACE_KEY_BASE: u64 = 1u64 << 32;

// Standard handles
pub const STD_INPUT_HANDLE: u64 = 0xFFFF_FFF6;
pub const STD_OUTPUT_HANDLE: u64 = 0xFFFF_FFF5;
pub const STD_ERROR_HANDLE: u64 = 0xFFFF_FFF4;
pub const FILE_TYPE_CHAR: u64 = 0x0002;
pub const DEFAULT_CONSOLE_MODE: u32 = 0x0007;

// STARTUPINFO sizes
pub const STARTUPINFO_SIZE_X86: u32 = 68;
pub const STARTUPINFO_SIZE_X64: u32 = 104;

// Wait/timeout
pub const WAIT_TIMEOUT: u64 = 0x102;

// Windows error codes
pub const ERROR_SUCCESS: u64 = 0;
pub const ERROR_ACCESS_DENIED: u64 = 5;
pub const ERROR_INSUFFICIENT_BUFFER: u64 = 122;
pub const ERROR_ALREADY_EXISTS: u64 = 183;
pub const ERROR_BAD_LENGTH: u64 = 24;
pub const ERROR_BUFFER_OVERFLOW: u64 = 111;
pub const ERROR_ENVVAR_NOT_FOUND: u64 = 203;
pub const ERROR_FILE_NOT_FOUND: u64 = 2;
pub const ERROR_MOD_NOT_FOUND: u64 = 126;
pub const ERROR_INVALID_HANDLE: u64 = 6;
pub const ERROR_INVALID_ADDRESS: u64 = 487;
pub const ERROR_INVALID_LEVEL: u64 = 124;
pub const ERROR_INVALID_PARAMETER: u64 = 87;
pub const ERROR_INVALID_SERVICE_CONTROL: u64 = 1052;
pub const ERROR_NO_DATA: u64 = 232;
pub const ERROR_NO_SUCH_DOMAIN: u64 = 1355;
pub const ERROR_NOT_OWNER: u64 = 288;
pub const ERROR_TOO_MANY_POSTS: u64 = 298;
pub const ERROR_SERVICE_ALREADY_RUNNING: u64 = 1056;
pub const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: u64 = 1061;
pub const ERROR_SERVICE_DOES_NOT_EXIST: u64 = 1060;
pub const ERROR_SERVICE_EXISTS: u64 = 1073;
pub const ERROR_SERVICE_NOT_ACTIVE: u64 = 1062;
pub const ERROR_NO_MORE_FILES: u64 = 18;
pub const ERROR_MORE_DATA: u64 = 234;
pub const ERROR_NO_MORE_ITEMS: u64 = 259;
pub const ERROR_RESOURCE_DATA_NOT_FOUND: u64 = 1812;
pub const ERROR_RESOURCE_TYPE_NOT_FOUND: u64 = 1813;
pub const ERROR_RESOURCE_NAME_NOT_FOUND: u64 = 1814;
pub const ERROR_RESOURCE_LANG_NOT_FOUND: u64 = 1815;
pub const ERROR_UNSUPPORTED_TYPE: u64 = 1630;
pub const STILL_ACTIVE: u64 = 259;
pub const ERROR_TIMEOUT: u64 = 1460;

// HRESULT codes
pub const E_INVALIDARG_HRESULT: u64 = 0x8007_0057;
pub const REGDB_E_CLASSNOTREG_HRESULT: u64 = 0x8004_0154;

// RPC
pub const RPC_S_OK: u64 = 0;
pub const RPC_S_UUID_LOCAL_ONLY: u64 = 1824;

// Process information classes
pub const TH32CS_SNAPPROCESS: u64 = 0x0000_0002;
pub const PROCESS_BASIC_INFORMATION_CLASS: u64 = 0;
pub const PROCESS_IMAGE_FILE_NAME_CLASS: u64 = 27;
pub const PROCESS_DEBUG_PORT_CLASS: u64 = 30;
/// ProcessDebugObjectHandle returns STATUS_PORT_NOT_SET when not being debugged.
pub const STATUS_PORT_NOT_SET: u64 = 0xC000_0353;

// System information classes
pub const SYSTEM_BASIC_INFORMATION_CLASS: u64 = 0;
pub const SYSTEM_PROCESS_INFORMATION_CLASS: u64 = 5;

// Module flags
pub const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u64 = 0x0000_0004;

// CompareString results
pub const CSTR_LESS_THAN: u64 = 1;
pub const CSTR_EQUAL: u64 = 2;
pub const CSTR_GREATER_THAN: u64 = 3;

// File attributes
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
pub const INVALID_FILE_ATTRIBUTES: u64 = u32::MAX as u64;

// Memory allocation types
pub const MEM_RELEASE: u64 = 0x0000_8000;
pub const MEM_DECOMMIT: u64 = 0x0000_4000;
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_FREE: u32 = 0x10000;
pub const MEM_PRIVATE: u32 = 0x20000;
pub const MEM_MAPPED: u32 = 0x40000;
pub const MEM_IMAGE: u32 = 0x0100_0000;

// MUI
pub const MUI_LANGUAGE_ID: u32 = 0x0000_0004;
pub const MUI_LANGUAGE_NAME: u32 = 0x0000_0008;

// Page protection
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;

// File mapping
pub const FILE_MAP_COPY: u32 = 0x0001;
pub const FILE_MAP_WRITE: u32 = 0x0002;
pub const FILE_MAP_READ: u32 = 0x0004;

// Heap
pub const HEAP_ZERO_MEMORY: u64 = 0x0000_0008;
pub const LMEM_ZEROINIT: u64 = 0x0000_0040;

// Memory information
pub const MEMORY_BASIC_INFORMATION_CLASS: u64 = 0;
pub const SEC_IMAGE: u32 = 0x0100_0000;

// VARIANT sizes
pub const VARIANT_SIZE_X86: usize = 16;
pub const VARIANT_SIZE_X64: usize = 24;

// Time zone
pub const TIME_ZONE_ID_UNKNOWN: u64 = 0;

// FormatMessage
pub const FORMAT_MESSAGE_ALLOCATE_BUFFER: u64 = 0x0000_0100;

// CSIDL (shell folder) constants
pub const CSIDL_VALUE_MASK: u32 = 0x00FF;
pub const CSIDL_DESKTOP: u32 = 0x0000;
pub const CSIDL_PROGRAMS: u32 = 0x0002;
pub const CSIDL_PERSONAL: u32 = 0x0005;
pub const CSIDL_STARTUP: u32 = 0x0007;
pub const CSIDL_STARTMENU: u32 = 0x000B;
pub const CSIDL_DESKTOPDIRECTORY: u32 = 0x0010;
pub const CSIDL_FONTS: u32 = 0x0014;
pub const CSIDL_COMMON_STARTMENU: u32 = 0x0016;
pub const CSIDL_COMMON_PROGRAMS: u32 = 0x0017;
pub const CSIDL_COMMON_STARTUP: u32 = 0x0018;
pub const CSIDL_COMMON_DESKTOPDIRECTORY: u32 = 0x0019;
pub const CSIDL_APPDATA: u32 = 0x001A;
pub const CSIDL_LOCAL_APPDATA: u32 = 0x001C;
pub const CSIDL_COMMON_APPDATA: u32 = 0x0023;
pub const CSIDL_WINDOWS: u32 = 0x0024;
pub const CSIDL_SYSTEM: u32 = 0x0025;
pub const CSIDL_PROGRAM_FILES: u32 = 0x0026;
pub const CSIDL_MYPICTURES: u32 = 0x0027;
pub const CSIDL_PROFILE: u32 = 0x0028;
pub const CSIDL_SYSTEMX86: u32 = 0x0029;
pub const CSIDL_PROGRAM_FILESX86: u32 = 0x002A;
pub const CSIDL_PROGRAM_FILES_COMMON: u32 = 0x002B;
pub const CSIDL_PROGRAM_FILES_COMMONX86: u32 = 0x002C;

// Winsock
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 23;
pub const SOCKET_ERROR: u64 = u32::MAX as u64;
pub const INVALID_SOCKET: u64 = u32::MAX as u64;
pub const FIONBIO: u64 = 0x8004_667E;
pub const FIONREAD: u64 = 0x4004_667F;

// Engine internals
pub const GUID_RNG_SEED: u64 = 0xC0DE_CAFE_4755_4944;
pub const NATIVE_PROGRESS_INTERVAL_INSTRUCTIONS: u64 = 250_000;
pub const NATIVE_PROGRESS_TOP_BLOCK_LIMIT: usize = 8;
pub const NATIVE_LOOP_HISTORY_BLOCKS: usize = 512;
pub const NATIVE_LOOP_MIN_PERIOD_BLOCKS: usize = 2;
pub const NATIVE_LOOP_MAX_PERIOD_BLOCKS: usize = 24;
pub const NATIVE_LOOP_MIN_REPEATS: u64 = 3;
pub const NATIVE_LOOP_PHASE_DELTA_LIMIT: usize = 8;
pub const EMULATED_TIME_PROGRESS_INTERVAL_INSTRUCTIONS: u64 = 1_024;

// MSVCRT layout offsets
pub const MSVCRT_FMODE_OFFSET: u64 = 0x00;
pub const MSVCRT_COMMODE_OFFSET: u64 = 0x04;
pub const MSVCRT_APP_TYPE_OFFSET: u64 = 0x08;
pub const MSVCRT_CONTROLFP_OFFSET: u64 = 0x0C;
pub const MSVCRT_USER_MATHERR_OFFSET: u64 = 0x10;
pub const MSVCRT_ERRNO_OFFSET: u64 = 0x18;
pub const MSVCRT_ACMDLN_PTR_OFFSET: u64 = 0x20;
pub const MSVCRT_ARGV_ARRAY_OFFSET: u64 = 0x40;
pub const MSVCRT_ENVP_ARRAY_OFFSET: u64 = 0x80;
pub const MSVCRT_ONEXIT_TABLE_OFFSET: u64 = 0x100;
pub const MSVCRT_STRERROR_BUFFER_OFFSET: u64 = 0x200;
pub const MSVCRT_DEFAULT_CONTROLFP: u32 = 0x0009_001F;

// Epoch conversion
pub const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;

// WinHTTP query flags
pub const WINHTTP_QUERY_CONTENT_LENGTH: u32 = 5;
pub const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
pub const WINHTTP_QUERY_STATUS_TEXT: u32 = 20;
pub const WINHTTP_QUERY_RAW_HEADERS_CRLF: u32 = 22;
pub const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;
pub const WINHTTP_ACCESS_TYPE_NO_PROXY: u32 = 1;

// Service control manager
pub const SC_STATUS_PROCESS_INFO: u64 = 0;
pub const SERVICE_CONFIG_DESCRIPTION: u64 = 1;
pub const SERVICE_CONFIG_FAILURE_ACTIONS: u64 = 2;
pub const SERVICE_CONFIG_DELAYED_AUTO_START_INFO: u64 = 3;
pub const SERVICE_CONFIG_FAILURE_ACTIONS_FLAG: u64 = 4;
pub const SERVICE_CONFIG_SERVICE_SID_INFO: u64 = 5;
pub const SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO: u64 = 6;
pub const SERVICE_CONFIG_PRESHUTDOWN_INFO: u64 = 7;
pub const SERVICE_ACTIVE: u32 = 0x0000_0001;
pub const SERVICE_INACTIVE: u32 = 0x0000_0002;
pub const SERVICE_STATE_ALL: u32 = SERVICE_ACTIVE | SERVICE_INACTIVE;
pub const SERVICE_STOPPED: u32 = 0x0000_0001;
pub const SERVICE_RUNNING: u32 = 0x0000_0004;
pub const SERVICE_PAUSED: u32 = 0x0000_0007;
pub const SERVICE_ACCEPT_STOP: u32 = 0x0000_0001;
pub const SERVICE_ACCEPT_PAUSE_CONTINUE: u32 = 0x0000_0002;
pub const SERVICE_ACCEPT_SHUTDOWN: u32 = 0x0000_0004;
pub const SERVICE_CONTROL_STOP: u32 = 0x0000_0001;
pub const SERVICE_CONTROL_PAUSE: u32 = 0x0000_0002;
pub const SERVICE_CONTROL_CONTINUE: u32 = 0x0000_0003;
pub const SERVICE_CONTROL_INTERROGATE: u32 = 0x0000_0004;
pub const SERVICE_CONTROL_SHUTDOWN: u32 = 0x0000_0005;
pub const SERVICE_CONTROL_PRESHUTDOWN: u32 = 0x0000_000F;

// Exception handling
pub const EXCEPTION_CONTINUE_EXECUTION_FILTER: i32 = -1;
pub const EXCEPTION_CONTINUE_SEARCH_FILTER: i32 = 0;
pub const EXCEPTION_EXECUTE_HANDLER_FILTER: i32 = 1;
pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;
pub const STATUS_STACK_BUFFER_OVERRUN: u32 = 0x8000_000A;
pub const X86_BREAKPOINT_VECTOR: u32 = 3;
pub const UNICORN_EXCP_DEBUG: u32 = 0x10002;
pub const MSVC_CXX_EXCEPTION: u32 = 0xE06D_7363;

// Baseline modules loaded before the main module
pub const STARTUP_BASELINE_MODULES: &[&str] = &[
    "ntdll.dll",
    "kernel32.dll",
    "lpk.dll",
    "usp10.dll",
    "kernelbase.dll",
    "shlwapi.dll",
    "shell32.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "msvcrt.dll",
    "ws2_32.dll",
    "psapi.dll",
];
