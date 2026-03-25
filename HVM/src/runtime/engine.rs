use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::c_void;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::Ipv4Addr;

use encoding::all::{GBK, MAC_ROMAN, UTF_16LE, UTF_8, WINDOWS_1252};
use encoding::{DecoderTrap, EncoderTrap, EncodingRef};
use encoding_index_simpchinese::gb18030 as gbk_index;
use goblin::pe::PE;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use serde_json::{json, Map};

use crate::arch::{arch_spec, ArchSpec};
use crate::config::{EngineConfig, EntryArgument, HttpResponseHeader, VolumeMount};
use crate::environment_profile::EnvironmentProfile;
use crate::error::VmError;
use crate::hooks::base::{CallConv, HookDefinition};
use crate::hooks::families::core::ntdll::{
    STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_FILE_FOR_SECTION, STATUS_INVALID_HANDLE,
    STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_EXISTS, STATUS_SUCCESS,
};
use crate::hooks::families::shell_services::shell32::{
    SEE_MASK_NOCLOSEPROCESS, SHELL_EXECUTE_SUCCESS,
};
use crate::hooks::register_all_family_hooks;
use crate::hooks::registry::HookRegistry;
use crate::managers::crypto_manager::CryptoManager;
use crate::managers::device_manager::DeviceManager;
use crate::managers::file_mapping_manager::FileMappingManager;
use crate::managers::handle_table::HandleTable;
use crate::managers::heap_manager::HeapManager;
use crate::managers::module_manager::ModuleManager;
use crate::managers::network_manager::NetworkManager;
use crate::managers::process_manager::ProcessManager;
use crate::managers::registry_manager::RegistryManager;
use crate::managers::service_manager::ServiceManager;
use crate::managers::time_manager::TimeManager;
use crate::managers::tls_manager::TlsManager;
use crate::memory::manager::{MemoryManager, PAGE_SIZE, PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::models::{ModuleRecord, RunResult, RunStopReason};
use crate::pe::imports::collect_import_bindings;
use crate::runtime::api_logger::{AddressRef, ApiLogArg, ApiLogger};
use crate::runtime::gbk_compat::python_gbk_pair_is_valid;
use crate::runtime::profiler::RuntimeProfiler;
use crate::runtime::scheduler::{ThreadScheduler, WAIT_IO_COMPLETION};
use crate::runtime::thread_context::{deserialize_register_context, serialize_register_context};
use crate::runtime::unicorn::{
    UcEngine, UnicornApi, X86Mmr, UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE, UC_X86_REG_CS,
    UC_X86_REG_DS, UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDI,
    UC_X86_REG_EDX, UC_X86_REG_EFLAGS, UC_X86_REG_EIP, UC_X86_REG_ES, UC_X86_REG_ESI,
    UC_X86_REG_ESP, UC_X86_REG_FS, UC_X86_REG_GDTR, UC_X86_REG_GS, UC_X86_REG_GS_BASE,
    UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX, UC_X86_REG_RBP, UC_X86_REG_RBX, UC_X86_REG_RCX,
    UC_X86_REG_RDI, UC_X86_REG_RDX, UC_X86_REG_RFLAGS, UC_X86_REG_RIP, UC_X86_REG_RSI,
    UC_X86_REG_RSP, UC_X86_REG_SS,
};
use crate::runtime::windows_env::WindowsProcessEnvironment;

include!("engine/module_list.rs");
#[path = "engine/hooks/com/mod.rs"]
mod com;
#[path = "engine/hooks/core/mod.rs"]
mod core;
#[path = "engine/hooks/crt/mod.rs"]
mod crt;
#[path = "engine/hooks/device/mod.rs"]
mod device;
#[path = "engine/hooks/family_dispatch.rs"]
mod family_dispatch;
#[path = "engine/hooks/graphics/mod.rs"]
mod graphics;
#[path = "engine/hooks/network/mod.rs"]
mod network;
#[path = "engine/hooks/security/mod.rs"]
mod security;
#[path = "engine/shared/mod.rs"]
mod shared;
#[path = "engine/hooks/shell_services/mod.rs"]
mod shell_services;
#[path = "engine/hooks/ui/mod.rs"]
mod ui;

use shared::RemoteShellcodeThread;
use ui::User32State;
use utilities::{
    arg, compare_ci, detect_runtime_architecture, is_std_handle, non_empty, seek_file, unicorn_prot,
};
use x86_interpreter_helpers::X86State;

const DLL_PROCESS_ATTACH: u64 = 1;
const DLL_PROCESS_DETACH: u64 = 0;
const DLL_THREAD_ATTACH: u64 = 2;
const DLL_THREAD_DETACH: u64 = 3;
const PROCESS_HANDLE_PSEUDO: u64 = 0xFFFF_FFFF;
const SHELL_PROCESS_SPACE_KEY_BASE: u64 = 1u64 << 32;
const STD_INPUT_HANDLE: u64 = 0xFFFF_FFF6;
const STD_OUTPUT_HANDLE: u64 = 0xFFFF_FFF5;
const STD_ERROR_HANDLE: u64 = 0xFFFF_FFF4;
const FILE_TYPE_CHAR: u64 = 0x0002;
const DEFAULT_CONSOLE_MODE: u32 = 0x0007;
const STARTUPINFO_SIZE_X86: u32 = 68;
const STARTUPINFO_SIZE_X64: u32 = 104;
const WAIT_TIMEOUT: u64 = 0x102;
const ERROR_SUCCESS: u64 = 0;
const ERROR_ACCESS_DENIED: u64 = 5;
const ERROR_INSUFFICIENT_BUFFER: u64 = 122;
const ERROR_ALREADY_EXISTS: u64 = 183;
const ERROR_BAD_LENGTH: u64 = 24;
const ERROR_BUFFER_OVERFLOW: u64 = 111;
const ERROR_ENVVAR_NOT_FOUND: u64 = 203;
const ERROR_FILE_NOT_FOUND: u64 = 2;
const ERROR_INVALID_HANDLE: u64 = 6;
const ERROR_INVALID_ADDRESS: u64 = 487;
const ERROR_INVALID_LEVEL: u64 = 124;
const ERROR_INVALID_PARAMETER: u64 = 87;
const ERROR_INVALID_SERVICE_CONTROL: u64 = 1052;
const ERROR_NO_DATA: u64 = 232;
const ERROR_NO_SUCH_DOMAIN: u64 = 1355;
const ERROR_NOT_OWNER: u64 = 288;
const ERROR_SERVICE_ALREADY_RUNNING: u64 = 1056;
const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: u64 = 1061;
const ERROR_SERVICE_DOES_NOT_EXIST: u64 = 1060;
const ERROR_SERVICE_NOT_ACTIVE: u64 = 1062;
const ERROR_NO_MORE_FILES: u64 = 18;
const ERROR_MORE_DATA: u64 = 234;
const ERROR_NO_MORE_ITEMS: u64 = 259;
const STILL_ACTIVE: u64 = 259;
const ERROR_TIMEOUT: u64 = 1460;
const E_INVALIDARG_HRESULT: u64 = 0x8007_0057;
const REGDB_E_CLASSNOTREG_HRESULT: u64 = 0x8004_0154;
const RPC_S_OK: u64 = 0;
const RPC_S_UUID_LOCAL_ONLY: u64 = 1824;
const TH32CS_SNAPPROCESS: u64 = 0x0000_0002;
const PROCESS_BASIC_INFORMATION_CLASS: u64 = 0;
const PROCESS_IMAGE_FILE_NAME_CLASS: u64 = 27;
const SYSTEM_BASIC_INFORMATION_CLASS: u64 = 0;
const SYSTEM_PROCESS_INFORMATION_CLASS: u64 = 5;
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u64 = 0x0000_0004;
const CSTR_LESS_THAN: u64 = 1;
const CSTR_EQUAL: u64 = 2;
const CSTR_GREATER_THAN: u64 = 3;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const INVALID_FILE_ATTRIBUTES: u64 = u32::MAX as u64;
const MEM_RELEASE: u64 = 0x0000_8000;
const MEM_DECOMMIT: u64 = 0x0000_4000;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_FREE: u32 = 0x10000;
const MEM_PRIVATE: u32 = 0x20000;
const MEM_MAPPED: u32 = 0x40000;
const MEM_IMAGE: u32 = 0x0100_0000;
const MUI_LANGUAGE_ID: u32 = 0x0000_0004;
const MUI_LANGUAGE_NAME: u32 = 0x0000_0008;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;
const FILE_MAP_COPY: u32 = 0x0001;
const FILE_MAP_WRITE: u32 = 0x0002;
const FILE_MAP_READ: u32 = 0x0004;
const INVALID_HANDLE_VALUE: u64 = u32::MAX as u64;
const HEAP_ZERO_MEMORY: u64 = 0x0000_0008;
const LMEM_ZEROINIT: u64 = 0x0000_0040;
const MEMORY_BASIC_INFORMATION_CLASS: u64 = 0;
const SEC_IMAGE: u32 = 0x0100_0000;
const VARIANT_SIZE_X86: usize = 16;
const VARIANT_SIZE_X64: usize = 24;
const TIME_ZONE_ID_UNKNOWN: u64 = 0;
const FORMAT_MESSAGE_ALLOCATE_BUFFER: u64 = 0x0000_0100;
const CSIDL_VALUE_MASK: u32 = 0x00FF;
const CSIDL_DESKTOP: u32 = 0x0000;
const CSIDL_PROGRAMS: u32 = 0x0002;
const CSIDL_PERSONAL: u32 = 0x0005;
const CSIDL_STARTUP: u32 = 0x0007;
const CSIDL_STARTMENU: u32 = 0x000B;
const CSIDL_DESKTOPDIRECTORY: u32 = 0x0010;
const CSIDL_FONTS: u32 = 0x0014;
const CSIDL_COMMON_STARTMENU: u32 = 0x0016;
const CSIDL_COMMON_PROGRAMS: u32 = 0x0017;
const CSIDL_COMMON_STARTUP: u32 = 0x0018;
const CSIDL_COMMON_DESKTOPDIRECTORY: u32 = 0x0019;
const CSIDL_APPDATA: u32 = 0x001A;
const CSIDL_LOCAL_APPDATA: u32 = 0x001C;
const CSIDL_COMMON_APPDATA: u32 = 0x0023;
const CSIDL_WINDOWS: u32 = 0x0024;
const CSIDL_SYSTEM: u32 = 0x0025;
const CSIDL_PROGRAM_FILES: u32 = 0x0026;
const CSIDL_MYPICTURES: u32 = 0x0027;
const CSIDL_PROFILE: u32 = 0x0028;
const CSIDL_SYSTEMX86: u32 = 0x0029;
const CSIDL_PROGRAM_FILESX86: u32 = 0x002A;
const CSIDL_PROGRAM_FILES_COMMON: u32 = 0x002B;
const CSIDL_PROGRAM_FILES_COMMONX86: u32 = 0x002C;
const AF_INET: u16 = 2;
const SOCKET_ERROR: u64 = u32::MAX as u64;
const INVALID_SOCKET: u64 = u32::MAX as u64;
const FIONBIO: u64 = 0x8004_667E;
const GUID_RNG_SEED: u64 = 0xC0DE_CAFE_4755_4944;
const NATIVE_PROGRESS_INTERVAL_INSTRUCTIONS: u64 = 250_000;
const NATIVE_PROGRESS_TOP_BLOCK_LIMIT: usize = 8;
const NATIVE_LOOP_HISTORY_BLOCKS: usize = 128;
const NATIVE_LOOP_MIN_PERIOD_BLOCKS: usize = 2;
const NATIVE_LOOP_MAX_PERIOD_BLOCKS: usize = 24;
const NATIVE_LOOP_MIN_REPEATS: u64 = 3;
const NATIVE_LOOP_PHASE_DELTA_LIMIT: usize = 8;
const EMULATED_TIME_PROGRESS_INTERVAL_INSTRUCTIONS: u64 = 1_024;
const MSVCRT_FMODE_OFFSET: u64 = 0x00;
const MSVCRT_COMMODE_OFFSET: u64 = 0x04;
const MSVCRT_APP_TYPE_OFFSET: u64 = 0x08;
const MSVCRT_CONTROLFP_OFFSET: u64 = 0x0C;
const MSVCRT_USER_MATHERR_OFFSET: u64 = 0x10;
const MSVCRT_ERRNO_OFFSET: u64 = 0x18;
const MSVCRT_ACMDLN_PTR_OFFSET: u64 = 0x20;
const MSVCRT_ARGV_ARRAY_OFFSET: u64 = 0x40;
const MSVCRT_ENVP_ARRAY_OFFSET: u64 = 0x80;
const MSVCRT_ONEXIT_TABLE_OFFSET: u64 = 0x100;
const MSVCRT_STRERROR_BUFFER_OFFSET: u64 = 0x200;
const MSVCRT_DEFAULT_CONTROLFP: u32 = 0x0009_001F;
const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const WINHTTP_QUERY_CONTENT_LENGTH: u32 = 5;
const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
const WINHTTP_QUERY_STATUS_TEXT: u32 = 20;
const WINHTTP_QUERY_RAW_HEADERS_CRLF: u32 = 22;
const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;
const WINHTTP_ACCESS_TYPE_NO_PROXY: u32 = 1;
const SC_STATUS_PROCESS_INFO: u64 = 0;
const SERVICE_CONFIG_DESCRIPTION: u64 = 1;
const SERVICE_CONFIG_FAILURE_ACTIONS: u64 = 2;
const SERVICE_CONFIG_DELAYED_AUTO_START_INFO: u64 = 3;
const SERVICE_CONFIG_FAILURE_ACTIONS_FLAG: u64 = 4;
const SERVICE_CONFIG_SERVICE_SID_INFO: u64 = 5;
const SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO: u64 = 6;
const SERVICE_CONFIG_PRESHUTDOWN_INFO: u64 = 7;
const SERVICE_ACTIVE: u32 = 0x0000_0001;
const SERVICE_INACTIVE: u32 = 0x0000_0002;
const SERVICE_STATE_ALL: u32 = SERVICE_ACTIVE | SERVICE_INACTIVE;
const SERVICE_STOPPED: u32 = 0x0000_0001;
const SERVICE_RUNNING: u32 = 0x0000_0004;
const SERVICE_PAUSED: u32 = 0x0000_0007;
const SERVICE_ACCEPT_STOP: u32 = 0x0000_0001;
const SERVICE_ACCEPT_PAUSE_CONTINUE: u32 = 0x0000_0002;
const SERVICE_ACCEPT_SHUTDOWN: u32 = 0x0000_0004;
const SERVICE_CONTROL_STOP: u32 = 0x0000_0001;
const SERVICE_CONTROL_PAUSE: u32 = 0x0000_0002;
const SERVICE_CONTROL_CONTINUE: u32 = 0x0000_0003;
const SERVICE_CONTROL_INTERROGATE: u32 = 0x0000_0004;
const SERVICE_CONTROL_SHUTDOWN: u32 = 0x0000_0005;
const SERVICE_CONTROL_PRESHUTDOWN: u32 = 0x0000_000F;
const EXCEPTION_CONTINUE_EXECUTION_FILTER: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH_FILTER: i32 = 0;
const EXCEPTION_EXECUTE_HANDLER_FILTER: i32 = 1;
const MSVC_CXX_EXCEPTION: u32 = 0xE06D_7363;
const STARTUP_BASELINE_MODULES: &[&str] = &[
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

#[derive(Debug)]
struct FileHandleState {
    file: std::fs::File,
    path: String,
    writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FindFileEntry {
    file_name: String,
    attributes: u32,
    size: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FindHandleState {
    entries: Vec<FindFileEntry>,
    cursor: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct VolumeFindHandleState {
    entries: Vec<String>,
    cursor: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceHandleState {
    path: String,
    physical_drive_index: Option<u32>,
    position: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SetupDeviceInfoSetState {
    devices: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountedVolume {
    host_path: std::path::PathBuf,
    guest_path: String,
    guest_components: Vec<String>,
    recursive: bool,
    host_is_dir: bool,
    priority: u8,
}

#[derive(Debug, Default, Clone)]
struct MsvcrtOnExitTable {
    storage: Option<u64>,
    capacity: usize,
    functions: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyntheticProcessIdentity {
    pid: u32,
    parent_pid: u32,
    image_path: String,
    command_line: String,
    current_directory: String,
}

impl SyntheticProcessIdentity {
    fn image_name(&self) -> String {
        let text = if self.image_path.is_empty() {
            self.command_line.as_str()
        } else {
            self.image_path.as_str()
        };
        text.rsplit(['\\', '/'])
            .find(|part| !part.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| text.to_string())
    }

    fn display_path(&self) -> String {
        if self.image_path.is_empty() {
            self.command_line.clone()
        } else {
            self.image_path.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolhelpProcessEntry {
    pid: u32,
    parent_pid: u32,
    thread_count: u32,
    image_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolhelpProcessSnapshot {
    entries: Vec<ToolhelpProcessEntry>,
    next_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VirtualAllocationSegment {
    base: u64,
    size: u64,
    state: u32,
    protect: u32,
}

impl VirtualAllocationSegment {
    fn end(&self) -> u64 {
        self.base + self.size
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VirtualAllocationRecord {
    allocation_base: u64,
    allocation_size: u64,
    allocation_protect: u32,
    allocation_type: u32,
    region_type: u32,
    segments: Vec<VirtualAllocationSegment>,
}

impl VirtualAllocationRecord {
    fn end(&self) -> u64 {
        self.allocation_base + self.allocation_size
    }

    fn contains(&self, address: u64) -> bool {
        self.allocation_base <= address && address < self.end()
    }

    fn segment_for_address(&self, address: u64) -> Option<&VirtualAllocationSegment> {
        self.segments
            .iter()
            .find(|segment| segment.base <= address && address < segment.end())
    }

    fn replace_range(&mut self, start: u64, size: u64, state: u32, protect: u32) -> bool {
        let end = start.saturating_add(size);
        if start < self.allocation_base || end > self.end() || start >= end {
            return false;
        }

        let mut cursor = start;
        let mut replacement = Vec::with_capacity(self.segments.len() + 2);
        for segment in &self.segments {
            if segment.end() <= start || segment.base >= end {
                replacement.push(*segment);
                continue;
            }

            let overlap_start = segment.base.max(start);
            let overlap_end = segment.end().min(end);
            if overlap_start > cursor {
                return false;
            }
            if segment.base < overlap_start {
                replacement.push(VirtualAllocationSegment {
                    base: segment.base,
                    size: overlap_start - segment.base,
                    state: segment.state,
                    protect: segment.protect,
                });
            }
            replacement.push(VirtualAllocationSegment {
                base: overlap_start,
                size: overlap_end - overlap_start,
                state,
                protect,
            });
            if overlap_end < segment.end() {
                replacement.push(VirtualAllocationSegment {
                    base: overlap_end,
                    size: segment.end() - overlap_end,
                    state: segment.state,
                    protect: segment.protect,
                });
            }
            cursor = overlap_end;
        }
        if cursor != end {
            return false;
        }
        self.segments = Self::merge_segments(replacement);
        true
    }

    fn merge_segments(segments: Vec<VirtualAllocationSegment>) -> Vec<VirtualAllocationSegment> {
        let mut merged: Vec<VirtualAllocationSegment> = Vec::with_capacity(segments.len());
        for segment in segments.into_iter().filter(|segment| segment.size != 0) {
            if let Some(previous) = merged.last_mut() {
                if previous.end() == segment.base
                    && previous.state == segment.state
                    && previous.protect == segment.protect
                {
                    previous.size += segment.size;
                    continue;
                }
            }
            merged.push(segment);
        }
        merged
    }
}

#[derive(Debug)]
struct SyntheticProcessSpace {
    memory: MemoryManager,
    process_env: WindowsProcessEnvironment,
    modules: Vec<ModuleRecord>,
    virtual_allocations: BTreeMap<u64, VirtualAllocationRecord>,
}

impl SyntheticProcessSpace {
    fn new(arch: &'static ArchSpec) -> Self {
        Self {
            memory: MemoryManager::for_arch(arch),
            process_env: WindowsProcessEnvironment::for_tests(arch),
            modules: Vec::new(),
            virtual_allocations: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryInvocation {
    NativeEntrypoint,
    Export,
}

#[derive(Debug, Clone)]
struct PendingContextRestore {
    context_address: u64,
    registers: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
struct PendingX86SehUnwind {
    context_address: u64,
    registers: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingMsvcrtInitterm {
    entry_rsp: u64,
    resume_rsp: u64,
    return_address: u64,
    next_cursor: u64,
    last: u64,
    stop_on_nonzero: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingUser32TimerCallback {
    entry_rsp: u64,
    resume_rsp: u64,
    return_address: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingUser32SendMessageCallback {
    entry_rsp: u64,
    resume_rsp: u64,
    return_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeEnvironmentVariable {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MutexState {
    owner_tid: Option<u32>,
    recursion_count: u32,
    abandoned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DynamicCodeWriteObservation {
    source: String,
    remote: bool,
    source_buffer: u64,
    target_address: u64,
    size: u64,
    dump_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DynamicCodeProtectObservation {
    source: String,
    remote: bool,
    address: u64,
    size: u64,
    old_protect: u32,
    new_protect: u32,
    became_executable: bool,
    dump_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DynamicCodeThreadObservation {
    trigger: String,
    tid: u32,
    handle: u32,
    start_address: u64,
    parameter: u64,
    state: String,
    dump_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DynamicCodeRegionActivity {
    process_key: u64,
    allocation_base: u64,
    region_base: u64,
    region_size: u64,
    region_type: u32,
    last_stage: String,
    write: Option<DynamicCodeWriteObservation>,
    protect: Option<DynamicCodeProtectObservation>,
    thread: Option<DynamicCodeThreadObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageHashBaseline {
    capture_size: u64,
    hash: u64,
}

/// Owns the Rust runtime scaffold that will replace the Python virtual execution engine.
#[derive(Debug)]
pub struct VirtualExecutionEngine {
    arch: &'static ArchSpec,
    config: EngineConfig,
    environment_profile: EnvironmentProfile,
    hooks: HookRegistry,
    modules: ModuleManager,
    scheduler: ThreadScheduler,
    process_env: WindowsProcessEnvironment,
    processes: ProcessManager,
    registry: RegistryManager,
    file_mappings: FileMappingManager,
    api_logger: ApiLogger,
    runtime_profiler: RuntimeProfiler,
    api_call_counts: BTreeMap<String, u64>,
    main_module: Option<ModuleRecord>,
    entry_module: Option<ModuleRecord>,
    parent_process: Option<SyntheticProcessIdentity>,
    entry_address: Option<u64>,
    entry_arguments: Vec<u64>,
    entry_invocation: EntryInvocation,
    entry_module_requires_attach: bool,
    command_line: String,
    current_directory: std::path::PathBuf,
    current_directory_host: std::path::PathBuf,
    environment_variables: BTreeMap<String, RuntimeEnvironmentVariable>,
    main_thread_tid: Option<u32>,
    instruction_count: u64,
    exit_code: Option<u32>,
    stop_reason: Option<RunStopReason>,
    process_exit_requested: bool,
    last_error: u32,
    top_level_exception_filter: u64,
    tls: TlsManager,
    time: TimeManager,
    heaps: HeapManager,
    devices: DeviceManager,
    network: NetworkManager,
    services: ServiceManager,
    crypto: CryptoManager,
    http_response_rule_hits: BTreeMap<usize, u64>,
    wts_server_handles: BTreeSet<u32>,
    mutex_handles: BTreeSet<u32>,
    mutex_handle_targets: BTreeMap<u32, u32>,
    mutex_states: BTreeMap<u32, MutexState>,
    named_mutexes: BTreeMap<String, u32>,
    dynamic_library_refs: BTreeMap<u64, u32>,
    startup_pinned_modules: BTreeSet<u64>,
    attached_process_modules: BTreeSet<u64>,
    pending_thread_attach: BTreeSet<u32>,
    started_threads: BTreeSet<u32>,
    process_handles: BTreeMap<u32, u32>,
    process_spaces: BTreeMap<u64, SyntheticProcessSpace>,
    virtual_allocations: BTreeMap<u64, VirtualAllocationRecord>,
    process_snapshots: BTreeMap<u32, ToolhelpProcessSnapshot>,
    device_handles: BTreeMap<u32, DeviceHandleState>,
    setup_device_sets: BTreeMap<u32, SetupDeviceInfoSetState>,
    mounted_volumes: Vec<MountedVolume>,
    token_handles: BTreeSet<u32>,
    next_file_handle: u32,
    next_object_handle: u32,
    file_handles: BTreeMap<u32, FileHandleState>,
    find_handles: BTreeMap<u32, FindHandleState>,
    volume_find_handles: BTreeMap<u32, VolumeFindHandleState>,
    global_atoms: BTreeMap<u16, String>,
    next_atom: u16,
    inet_ntoa_buffer: Option<u64>,
    shell_imalloc: Option<u64>,
    user32_state: User32State,
    msvcrt_globals_base: Option<u64>,
    msvcrt_onexit_tables: BTreeMap<u64, MsvcrtOnExitTable>,
    msvcrt_rand_seed: u32,
    guid_rng: StdRng,
    native_trace: NativeTraceState,
    memory_dump_sequence: u64,
    dynamic_code_activities: BTreeMap<(u64, u64), DynamicCodeRegionActivity>,
    image_hash_baselines: BTreeMap<(u64, u64), ImageHashBaseline>,
    remote_shellcode_threads: BTreeMap<u32, RemoteShellcodeThread>,
    pending_context_restore: Option<PendingContextRestore>,
    pending_x86_seh_unwind: Option<PendingX86SehUnwind>,
    pending_msvcrt_initterm: Vec<PendingMsvcrtInitterm>,
    pending_user32_timer_callbacks: Vec<PendingUser32TimerCallback>,
    pending_user32_sendmessage_callbacks: Vec<PendingUser32SendMessageCallback>,
    defer_api_return: bool,
    thread_yield_requested: bool,
    force_native_return: bool,
    startup_sequence_completed: bool,
    loaded: bool,
    native_return_sentinel: u64,
    unicorn: Option<Box<UnicornApi>>,
    unicorn_handle: Option<*mut UcEngine>,
    unicorn_block_hook_installed: bool,
    unicorn_code_hook_installed: bool,
    unicorn_mem_write_hook_installed: bool,
    unicorn_mem_prot_hook_installed: bool,
    unicorn_mem_unmapped_hook_installed: bool,
}

impl VirtualExecutionEngine {
    /// Builds a new Rust virtual execution engine from the Python-compatible config shape.
    pub fn new(mut config: EngineConfig) -> Result<Self, VmError> {
        let arch = detect_runtime_architecture(&config.main_module)?;
        let mut environment_profile = match config.environment_profile.as_ref() {
            Some(path) => EnvironmentProfile::load(path)?,
            None => EnvironmentProfile::default(),
        };
        if let Some(overrides) = config.environment_overrides.as_ref() {
            environment_profile.apply_overrides(overrides);
        }
        for search_path in &environment_profile.module_search_paths {
            if !config
                .module_search_paths
                .iter()
                .any(|path| path == search_path)
            {
                config.module_search_paths.push(search_path.clone());
            }
        }
        let mut hooks = HookRegistry::for_tests();
        register_all_family_hooks(&mut hooks);
        let mut modules = ModuleManager::for_arch(arch);
        let heaps = HeapManager::new(modules.memory_mut())?;
        let mut registry = RegistryManager::new();
        environment_profile.apply_to_registry(&mut registry)?;
        let user32_state = User32State::from_environment_profile(&environment_profile);
        let mounted_volumes = Self::build_runtime_volume_mounts(&config, &environment_profile);
        let service_inventory = environment_profile.services.clone();
        let native_return_sentinel = modules
            .memory_mut()
            .reserve(PAGE_SIZE, None, "sentinel", true)?;
        modules
            .memory_mut()
            .write(native_return_sentinel, &[0xC3])?;
        let thread_exit_sentinel =
            modules
                .memory_mut()
                .reserve(PAGE_SIZE, None, "thread_exit_sentinel", true)?;
        modules.memory_mut().write(thread_exit_sentinel, &[0xC3])?;

        Ok(Self {
            arch,
            api_logger: ApiLogger::new(&config)?,
            runtime_profiler: RuntimeProfiler::from_env(&config),
            api_call_counts: BTreeMap::new(),
            config,
            environment_profile,
            hooks,
            modules,
            scheduler: ThreadScheduler::for_tests(),
            process_env: WindowsProcessEnvironment::for_tests(arch),
            processes: ProcessManager::for_tests(),
            registry,
            file_mappings: FileMappingManager::new(),
            main_module: None,
            entry_module: None,
            parent_process: None,
            entry_address: None,
            entry_arguments: Vec::new(),
            entry_invocation: EntryInvocation::NativeEntrypoint,
            entry_module_requires_attach: false,
            command_line: String::new(),
            current_directory: std::path::PathBuf::new(),
            current_directory_host: std::path::PathBuf::new(),
            environment_variables: BTreeMap::new(),
            main_thread_tid: None,
            instruction_count: 0,
            exit_code: None,
            stop_reason: None,
            process_exit_requested: false,
            last_error: 0,
            top_level_exception_filter: 0,
            tls: TlsManager::new(),
            time: TimeManager::default(),
            heaps,
            devices: DeviceManager::new(),
            network: NetworkManager::new(HandleTable::new(0xC000)),
            services: ServiceManager::new(HandleTable::new(0xE000), service_inventory),
            crypto: CryptoManager::new(HandleTable::new(0xD000)),
            http_response_rule_hits: BTreeMap::new(),
            wts_server_handles: BTreeSet::new(),
            mutex_handles: BTreeSet::new(),
            mutex_handle_targets: BTreeMap::new(),
            mutex_states: BTreeMap::new(),
            named_mutexes: BTreeMap::new(),
            dynamic_library_refs: BTreeMap::new(),
            startup_pinned_modules: BTreeSet::new(),
            attached_process_modules: BTreeSet::new(),
            pending_thread_attach: BTreeSet::new(),
            started_threads: BTreeSet::new(),
            process_handles: BTreeMap::new(),
            process_spaces: BTreeMap::new(),
            virtual_allocations: BTreeMap::new(),
            process_snapshots: BTreeMap::new(),
            device_handles: BTreeMap::new(),
            setup_device_sets: BTreeMap::new(),
            mounted_volumes,
            token_handles: BTreeSet::new(),
            next_file_handle: 0x1000,
            next_object_handle: 0x8004,
            file_handles: BTreeMap::new(),
            find_handles: BTreeMap::new(),
            volume_find_handles: BTreeMap::new(),
            global_atoms: BTreeMap::new(),
            next_atom: 0xC000,
            inet_ntoa_buffer: None,
            shell_imalloc: None,
            user32_state,
            msvcrt_globals_base: None,
            msvcrt_onexit_tables: BTreeMap::new(),
            msvcrt_rand_seed: 1,
            guid_rng: StdRng::seed_from_u64(GUID_RNG_SEED),
            native_trace: NativeTraceState::default(),
            memory_dump_sequence: 0,
            dynamic_code_activities: BTreeMap::new(),
            image_hash_baselines: BTreeMap::new(),
            remote_shellcode_threads: BTreeMap::new(),
            pending_context_restore: None,
            pending_x86_seh_unwind: None,
            pending_msvcrt_initterm: Vec::new(),
            pending_user32_timer_callbacks: Vec::new(),
            pending_user32_sendmessage_callbacks: Vec::new(),
            defer_api_return: false,
            thread_yield_requested: false,
            force_native_return: false,
            startup_sequence_completed: false,
            loaded: false,
            native_return_sentinel,
            unicorn: UnicornApi::load_default().ok().map(Box::new),
            unicorn_handle: None,
            unicorn_block_hook_installed: false,
            unicorn_code_hook_installed: false,
            unicorn_mem_write_hook_installed: false,
            unicorn_mem_prot_hook_installed: false,
            unicorn_mem_unmapped_hook_installed: false,
        })
    }

    /// Loads the configured main module and initializes the primary scheduler thread once.
    pub fn load(&mut self) -> Result<&ModuleRecord, VmError> {
        if !self.loaded {
            let configured_main_path = self.config.main_module.clone();
            let process_image_path = self.config.process_image_path().to_path_buf();
            let entry_module_path = self.config.entry_module_path().to_path_buf();
            let process_image = self.modules.load_runtime_main(
                process_image_path.clone(),
                &self.config,
                &mut self.hooks,
            )?;
            self.log_module_event("MODULE_LOAD", &process_image, "process_image")?;
            let configured_main_module = if configured_main_path == process_image_path {
                process_image.clone()
            } else {
                let module = self.modules.load_runtime_main(
                    configured_main_path.clone(),
                    &self.config,
                    &mut self.hooks,
                )?;
                self.log_module_event("MODULE_LOAD", &module, "configured_main")?;
                module
            };
            let entry_module = if entry_module_path == process_image_path {
                process_image.clone()
            } else if entry_module_path == configured_main_path {
                configured_main_module.clone()
            } else {
                let module = self.modules.load_runtime_main(
                    entry_module_path.clone(),
                    &self.config,
                    &mut self.hooks,
                )?;
                self.log_module_event("MODULE_LOAD", &module, "entry_module")?;
                module
            };
            self.ensure_supported_execution_architecture(&configured_main_module, "load")?;
            self.ensure_supported_execution_architecture(&entry_module, "load")?;
            self.preload_startup_baseline_modules()?;
            for preload in self.config.preload_modules.clone() {
                let module = self.modules.load_runtime_dependency(
                    &preload,
                    &self.config,
                    &mut self.hooks,
                )?;
                self.log_module_event("MODULE_LOAD", &module, "preload")?;
            }
            self.reserve_python_process_env_footprint()?;
            self.process_env =
                WindowsProcessEnvironment::from_reserved(self.modules.memory(), self.arch)?;
            self.entry_invocation = if self.config.uses_export_entry() {
                EntryInvocation::Export
            } else {
                EntryInvocation::NativeEntrypoint
            };
            self.entry_module_requires_attach = self.entry_invocation == EntryInvocation::Export
                && Self::module_looks_like_dll(&entry_module);
            self.entry_address = Some(self.resolve_entry_address(&entry_module)?);
            self.entry_arguments = self.prepare_entry_arguments(&entry_module)?;
            let runtime_process_image_path =
                if !self.environment_profile.machine.image_path.is_empty() {
                    self.environment_profile.machine.image_path.clone()
                } else {
                    process_image
                        .path
                        .as_ref()
                        .map(|path| path.to_string_lossy().to_string())
                        .unwrap_or_else(|| process_image.name.clone())
                };
            self.command_line = if !self.environment_profile.machine.command_line.is_empty() {
                self.environment_profile.machine.command_line.clone()
            } else if !self.config.command_line.is_empty() {
                self.config.command_line.clone()
            } else {
                runtime_process_image_path.clone()
            };
            self.current_directory = if !self
                .environment_profile
                .machine
                .current_directory
                .is_empty()
            {
                std::path::PathBuf::from(&self.environment_profile.machine.current_directory)
            } else {
                process_image
                    .path
                    .as_ref()
                    .and_then(|path| path.parent())
                    .unwrap_or_else(|| {
                        process_image_path
                            .parent()
                            .unwrap_or(std::path::Path::new("."))
                    })
                    .to_path_buf()
            };
            self.current_directory_host = self
                .resolve_absolute_runtime_path(&self.current_directory.to_string_lossy())
                .unwrap_or_else(|| self.current_directory.clone());
            self.ensure_virtual_windows_layout()?;
            self.parent_process = self.build_parent_process_identity();
            let dll_path = self.build_process_dll_path();
            let tmp_directory = self.temporary_directory_path();
            self.initialize_runtime_environment_variables(&dll_path, &tmp_directory)?;
            let environment = self.runtime_environment_entries();
            self.process_env
                .configure_process_parameters_with_runtime_details_and_environment(
                    &runtime_process_image_path,
                    &self.command_line,
                    &self.current_directory.to_string_lossy(),
                    &dll_path,
                    &environment,
                )?;
            self.process_env.sync_image_base(process_image.base);
            self.sync_process_environment_modules()?;
            self.refresh_known_data_imports()?;
            let main_thread = self
                .scheduler
                .register_main_thread_with_parameter(
                    self.entry_address.unwrap_or(entry_module.entrypoint),
                    self.entry_arguments.first().copied().unwrap_or(0),
                )
                .unwrap();
            let (stack_limit, stack_top, stack_base) = {
                let memory = self.modules.memory_mut();
                let (stack_allocation_base, stack_top) = memory.allocate_stack()?;
                let stack_base = stack_allocation_base + memory.layout().stack_size;
                (stack_allocation_base, stack_top, stack_base)
            };
            let stack_limit = self.register_initial_thread_stack_allocation(
                self.current_process_space_key(),
                stack_limit,
                stack_base,
                stack_top,
            )?;
            let thread_context = self
                .process_env
                .allocate_thread_teb(stack_base, stack_limit)?;
            self.process_env.sync_teb_client_id(
                thread_context.teb_base,
                self.current_process_id(),
                main_thread.tid,
            );
            self.initialize_scheduler_thread_context(main_thread.tid, thread_context, stack_top)?;
            if self.entry_invocation == EntryInvocation::Export && self.arch.is_x86() {
                let mut registers = self
                    .scheduler
                    .thread_snapshot(main_thread.tid)
                    .ok_or(VmError::RuntimeInvariant("main thread snapshot missing"))?
                    .registers;
                let saved_esp = registers
                    .get("esp")
                    .copied()
                    .ok_or(VmError::RuntimeInvariant("main thread ESP missing"))?;
                let mut frame = Vec::with_capacity((self.entry_arguments.len() + 1) * 4);
                frame.extend_from_slice(&(self.native_return_sentinel as u32).to_le_bytes());
                for value in &self.entry_arguments {
                    frame.extend_from_slice(&(*value as u32).to_le_bytes());
                }
                let new_esp = saved_esp
                    .checked_sub(frame.len() as u64)
                    .ok_or(VmError::RuntimeInvariant("native call stack underflow"))?;
                self.modules.memory_mut().write(new_esp, &frame)?;
                registers.insert("esp".to_string(), new_esp);
                registers.insert(
                    "eip".to_string(),
                    self.entry_address.unwrap_or(entry_module.entrypoint),
                );
                self.scheduler
                    .set_thread_registers(main_thread.tid, registers)
                    .ok_or(VmError::RuntimeInvariant(
                        "failed to seed x86 export bootstrap frame",
                    ))?;
            }
            self.scheduler
                .switch_to(main_thread.tid, &mut self.process_env)
                .unwrap();
            self.sync_native_support_state()?;
            self.main_thread_tid = Some(main_thread.tid);
            self.log_thread_event(
                "THREAD_CREATE",
                main_thread.tid,
                main_thread.handle,
                self.entry_address.unwrap_or(entry_module.entrypoint),
                self.entry_arguments.first().copied().unwrap_or(0),
                "ready",
            )?;
            self.log_thread_entry_dump_if_dynamic(
                "THREAD_START_DUMP",
                "THREAD_CREATE",
                main_thread.tid,
                main_thread.handle,
                self.entry_address.unwrap_or(entry_module.entrypoint),
                self.entry_arguments.first().copied().unwrap_or(0),
                "ready",
            )?;
            self.main_module = Some(process_image);
            self.entry_module = Some(entry_module);
            for module in self
                .current_process_modules()
                .into_iter()
                .filter(|module| !module.synthetic)
            {
                self.register_module_image_allocation(self.current_process_space_key(), &module)?;
            }
            self.loaded = true;
        }

        Ok(self.main_module.as_ref().unwrap())
    }

    /// Runs the minimal Rust execution flow and returns Python-compatible summary fields.
    pub fn run(&mut self) -> Result<RunResult, VmError> {
        let run_started = std::time::Instant::now();
        let main_module = self.load()?.clone();
        let entrypoint = self.entry_address.unwrap_or(main_module.entrypoint);
        self.reset_run_observation();
        if self.unicorn.is_some() {
            self.run_native_main()?;
        } else if self.arch.is_x64() {
            return Err(VmError::NativeExecution {
                op: "run",
                detail: "x64 execution requires a native Unicorn backend".to_string(),
            });
        } else {
            self.run_interpreter_scheduler_main()?;
        }
        if self.exit_code.is_none() {
            if let Some(main_tid) = self.main_thread_tid {
                self.exit_code = self.scheduler.thread_exit_code(main_tid).flatten();
            }
        }
        let stop_reason = self.resolve_run_stop_reason();
        self.log_native_summary(stop_reason)?;
        self.log_api_hotspot_summary()?;
        self.log_user32_hotspot_summary()?;
        self.log_modified_image_dumps(stop_reason.as_str())?;
        self.log_exit_executable_allocation_dumps(stop_reason.as_str())?;
        self.log_run_stop(stop_reason)?;
        self.log_process_exit(stop_reason.as_str())?;
        self.api_logger.flush()?;

        let result = RunResult {
            entrypoint,
            instructions: self.instruction_count,
            stopped: true,
            exit_code: self.exit_code,
            stop_reason,
        };
        self.runtime_profiler.emit_report(
            run_started.elapsed(),
            result.instructions,
            result.stop_reason,
        )?;
        Ok(result)
    }

    /// Returns the loaded main module when the runtime has been initialized.
    pub fn main_module(&self) -> Option<&ModuleRecord> {
        self.main_module.as_ref()
    }

    /// Returns the loaded execution module when it differs from the process image.
    pub fn entry_module(&self) -> Option<&ModuleRecord> {
        self.entry_module.as_ref()
    }

    /// Returns the resolved execution address after load.
    pub fn entry_address(&self) -> Option<u64> {
        self.entry_address
    }

    /// Returns the prepared argument vector used for the effective entry invocation.
    pub fn entry_arguments(&self) -> &[u64] {
        &self.entry_arguments
    }

    /// Returns the synthetic export registry wired into the current engine.
    pub fn hooks(&self) -> &HookRegistry {
        &self.hooks
    }

    /// Returns the scheduler owned by the current engine.
    pub fn scheduler(&self) -> &ThreadScheduler {
        &self.scheduler
    }

    /// Returns mutable scheduler access for runtime hook dispatch tests.
    pub fn scheduler_mut(&mut self) -> &mut ThreadScheduler {
        &mut self.scheduler
    }

    /// Returns the process-environment mirror owned by the current engine.
    pub fn process_env(&self) -> &WindowsProcessEnvironment {
        &self.process_env
    }

    /// Returns the child-process manager owned by the current engine.
    pub fn processes(&self) -> &ProcessManager {
        &self.processes
    }

    /// Returns the module manager owned by the current engine.
    pub fn modules(&self) -> &ModuleManager {
        &self.modules
    }

    /// Returns the effective command line the Rust runtime will expose after load.
    pub fn command_line(&self) -> &str {
        &self.command_line
    }

    /// Returns the registered main-thread identifier once the engine has loaded.
    pub fn main_thread_tid(&self) -> Option<u32> {
        self.main_thread_tid
    }

    /// Returns the registered main-thread handle once the engine has loaded.
    pub fn main_thread_handle(&self) -> Option<u32> {
        let tid = self.main_thread_tid?;
        self.scheduler
            .thread_snapshot(tid)
            .map(|thread| thread.handle)
    }

    /// Returns the synthetic return address used to terminate the primary x86 thread cleanly.
    pub fn main_thread_exit_sentinel(&self) -> u64 {
        self.native_return_sentinel
    }

    /// Returns the effective current directory derived during load.
    pub fn current_directory(&self) -> &std::path::Path {
        &self.current_directory
    }

    /// Returns whether a native Unicorn backend is available for current-process execution.
    pub fn has_native_unicorn(&self) -> bool {
        self.unicorn.is_some()
    }

    /// Returns the active Win32 last-error value mirrored into the current TEB.
    pub fn last_error(&self) -> u32 {
        self.last_error
    }

    /// Returns the process heap handle exposed by the runtime.
    pub fn process_heap_handle(&self) -> u32 {
        self.heaps.process_heap()
    }

    /// Returns the heap manager owned by the current engine.
    pub fn heap_manager(&self) -> &HeapManager {
        &self.heaps
    }

    /// Returns the device manager owned by the current engine.
    pub fn device_manager(&self) -> &DeviceManager {
        &self.devices
    }

    /// Returns the registry manager owned by the current engine.
    pub fn registry_manager(&self) -> &RegistryManager {
        &self.registry
    }

    /// Returns the network manager owned by the current engine.
    pub fn network_manager(&self) -> &NetworkManager {
        &self.network
    }

    /// Returns mutable network-manager access for runtime integration tests.
    pub fn network_manager_mut(&mut self) -> &mut NetworkManager {
        &mut self.network
    }

    /// Returns the crypto manager owned by the current engine.
    pub fn crypto_manager(&self) -> &CryptoManager {
        &self.crypto
    }

    /// Returns mutable crypto-manager access for runtime integration tests.
    pub fn crypto_manager_mut(&mut self) -> &mut CryptoManager {
        &mut self.crypto
    }

    /// Updates the active Win32 last-error value and mirrors it into the current TEB.
    pub fn set_last_error(&mut self, value: u32) {
        self.last_error = value;
        self.process_env.sync_last_error(value);
        let teb_last_error =
            self.process_env.current_teb() + self.process_env.offsets().teb_last_error as u64;
        if self.modules.memory().is_range_mapped(teb_last_error, 4) {
            let _ = self
                .modules
                .memory_mut()
                .write(teb_last_error, &value.to_le_bytes());
        } else {
            let _ = self.sync_native_support_state();
        }
    }

    fn record_instruction_retired(&mut self) {
        self.instruction_count = self.instruction_count.saturating_add(1);
        if self.instruction_count % EMULATED_TIME_PROGRESS_INTERVAL_INSTRUCTIONS == 0 {
            self.time.advance(1);
        }
    }

    fn remaining_run_budget(&self) -> u64 {
        self.config
            .max_instructions
            .max(1)
            .saturating_sub(self.instruction_count)
    }

    /// Binds one hook stub explicitly so runtime dispatch tests do not depend on sample imports.
    pub fn bind_hook_for_test(&mut self, module: &str, function: &str) -> u64 {
        let stub = self.hooks.bind_stub(module, function);
        let page = stub & !(PAGE_SIZE - 1);
        let page_was_mapped = self.modules.memory().is_range_mapped(page, PAGE_SIZE);
        if !page_was_mapped {
            self.modules
                .memory_mut()
                .map_region(
                    page,
                    PAGE_SIZE,
                    crate::memory::manager::PROT_READ | crate::memory::manager::PROT_EXEC,
                    "hook:test_stub",
                )
                .expect("failed to map hook test stub page");
        }
        self.modules
            .memory_mut()
            .write(
                stub,
                &[
                    0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                    0xCC, 0xCC, 0xCC,
                ],
            )
            .expect("failed to write hook test stub bytes");
        if let (Some(unicorn), Some(uc)) = (self.unicorn.as_deref(), self.unicorn_handle) {
            if !page_was_mapped {
                unsafe {
                    unicorn.mem_map_raw(
                        uc,
                        page,
                        PAGE_SIZE,
                        unicorn_prot(
                            crate::memory::manager::PROT_READ | crate::memory::manager::PROT_EXEC,
                        ),
                    )
                }
                .expect("failed to map hook test stub page into unicorn");
            }
            unsafe {
                unicorn.mem_write_raw(
                    uc,
                    stub,
                    &[
                        0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                        0xCC, 0xCC, 0xCC, 0xCC,
                    ],
                )
            }
            .expect("failed to write hook test stub bytes into unicorn");
        }
        stub
    }

    /// Allocates one executable page for native-execution smoke tests.
    pub fn allocate_executable_test_page(&mut self, preferred: u64) -> Result<u64, VmError> {
        self.modules
            .memory_mut()
            .reserve(PAGE_SIZE, Some(preferred), "native:test_page", false)
            .map_err(VmError::from)
    }

    /// Writes raw machine code or test bytes into the emulated address space.
    pub fn write_test_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), VmError> {
        self.modules
            .memory_mut()
            .write(address, bytes)
            .map_err(VmError::from)?;
        self.propagate_file_mapping_write(self.current_process_space_key(), address, bytes)
    }

    /// Executes one x86 native call using the current main-thread stack frame and returns EAX.
    pub fn call_native_for_test(&mut self, address: u64, args: &[u64]) -> Result<u64, VmError> {
        self.load()?;
        if self.hooks.is_bound_address(address) {
            return self.dispatch_bound_stub(address, args);
        }
        if self.arch.is_x64() {
            if self.unicorn.is_some() && !unicorn_context_active() {
                self.call_x64_native_with_unicorn(address, args)
            } else {
                Err(VmError::NativeExecution {
                    op: "run",
                    detail: "x64 execution requires a native Unicorn backend".to_string(),
                })
            }
        } else if self.unicorn.is_some() && !unicorn_context_active() {
            self.call_x86_native_with_unicorn(address, args)
        } else {
            self.call_x86_native_interpreter(address, args)
        }
    }

    /// Flushes buffered API and console logs so integration tests can inspect emitted traces.
    pub fn flush_api_logs_for_test(&mut self) -> Result<(), VmError> {
        self.api_logger.flush()
    }

    pub fn log_exit_executable_allocation_dumps_for_test(
        &mut self,
        reason: &str,
    ) -> Result<(), VmError> {
        self.log_exit_executable_allocation_dumps(reason)
    }

    pub fn capture_image_hash_baselines_for_test(&mut self) -> Result<(), VmError> {
        self.capture_current_process_image_hash_baselines()
    }

    pub fn log_modified_image_dumps_for_test(&mut self, reason: &str) -> Result<(), VmError> {
        self.log_modified_image_dumps(reason)
    }

    pub fn prepare_remote_thread_for_test(&mut self, tid: u32) -> Result<(), VmError> {
        self.prepare_remote_shellcode_thread_if_needed(tid)
    }

    fn reset_run_observation(&mut self) {
        self.stop_reason = None;
        self.process_exit_requested = false;
        self.native_trace.reset();
    }

    fn preload_startup_baseline_modules(&mut self) -> Result<(), VmError> {
        for module_name in STARTUP_BASELINE_MODULES {
            let existing = self.modules.get_loaded(module_name).cloned();
            let module =
                self.modules
                    .load_runtime_dependency(module_name, &self.config, &mut self.hooks)?;
            self.startup_pinned_modules.insert(module.base);
            if existing.is_none() {
                self.log_module_event("MODULE_LOAD", &module, "startup_baseline")?;
            }
        }
        Ok(())
    }

    fn request_thread_yield(&mut self, _reason: &str, preserve_api_frame: bool) {
        self.thread_yield_requested = true;
        if preserve_api_frame {
            self.defer_api_return = true;
        }
    }

    fn handle_requested_thread_yield(&mut self) {
        let _profile = self.runtime_profiler.start_scope("yield.handle_requested");
        let current_tick = self.time.current().tick_ms;
        if let Some(next_tick) = self.scheduler.next_wake_tick() {
            if next_tick > current_tick {
                self.time.advance(next_tick - current_tick);
            }
        }
        {
            let _profile = self
                .runtime_profiler
                .start_scope("scheduler.poll_blocked_threads");
            self.scheduler
                .poll_blocked_threads(self.time.current().tick_ms);
        }
        if let Some(tid) = self.scheduler.current_tid() {
            let _profile = self.runtime_profiler.start_scope("scheduler.switch_to");
            let _ = self.scheduler.switch_to(tid, &mut self.process_env);
        }
    }

    /// Dispatches one already-bound synthetic export stub through the live runtime state.
    pub fn dispatch_bound_stub(&mut self, address: u64, args: &[u64]) -> Result<u64, VmError> {
        let Some(definition) = self.hooks.definition_for_address(address).cloned() else {
            if let Some((module, function)) = self.hooks.binding_for_address(address) {
                let module = module.to_string();
                let function = function.to_string();
                let _ = self.log_unsupported_bound_stub(
                    address,
                    &module,
                    &function,
                    "missing hook definition",
                );
                if self.strict_unknown_api_policy() {
                    return Err(VmError::NativeExecution {
                        op: "dispatch",
                        detail: format!(
                            "unknown_api_policy={} rejected undefined hook {}!{} at 0x{address:X}",
                            self.config.unknown_api_policy, module, function
                        ),
                    });
                }
                return Ok(0);
            }
            return Err(VmError::NativeExecution {
                op: "dispatch",
                detail: format!("address 0x{address:X} is not a bound hook stub"),
            });
        };

        self.dispatch_bound_stub_with_definition(&definition, address, None, args)
    }

    /// Advances the scaffold scheduler until no runnable work remains or the instruction cap is spent.
    fn run_scheduler_loop(&mut self) -> Result<(), VmError> {
        let mut remaining = self.remaining_run_budget();
        if remaining == 0 {
            self.stop_reason = Some(RunStopReason::InstructionBudgetExhausted);
            return Ok(());
        }
        while remaining > 0 {
            {
                let _profile = self
                    .runtime_profiler
                    .start_scope("scheduler.poll_blocked_threads");
                self.scheduler
                    .poll_blocked_threads(self.time.current().tick_ms);
            }
            let Some(thread) = self.scheduler.next_ready_thread() else {
                if !self.scheduler.has_live_threads() {
                    break;
                }
                if let Some(next_tick) = self.scheduler.next_wake_tick() {
                    let current_tick = self.time.current().tick_ms;
                    if next_tick > current_tick {
                        self.time.advance(next_tick - current_tick);
                        continue;
                    }
                }
                break;
            };
            self.prepare_remote_shellcode_thread_if_needed(thread.tid)?;
            if self.scheduler.thread_state(thread.tid) != Some("running") {
                continue;
            }
            {
                let _profile = self.runtime_profiler.start_scope("scheduler.switch_to");
                let _ = self.scheduler.switch_to(thread.tid, &mut self.process_env);
            }
            let budget = remaining.min(self.scheduler.time_slice_instructions());
            let before = self.instruction_count;
            {
                let _profile = self
                    .runtime_profiler
                    .start_scope("interpreter.thread_slice_total");
                self.run_interpreter_thread_slice(thread.tid, budget)?;
            }
            let consumed = self.instruction_count.saturating_sub(before).max(1);
            if self.scheduler.thread_state(thread.tid) == Some("terminated")
                && self.started_threads.remove(&thread.tid)
            {
                let _ = self.dispatch_thread_notification(thread.tid, DLL_THREAD_DETACH);
            }
            remaining = remaining.saturating_sub(consumed);
            if Some(thread.tid) == self.main_thread_tid
                && self.scheduler.thread_state(thread.tid) == Some("terminated")
            {
                self.exit_code = self
                    .scheduler
                    .thread_exit_code(thread.tid)
                    .flatten()
                    .or(self.exit_code);
                if self.process_exit_requested || !self.scheduler.has_live_threads() {
                    break;
                }
            }
            self.time.advance(self.scheduler.time_slice_ms());
        }
        self.stop_reason = Some(if remaining == 0 {
            RunStopReason::InstructionBudgetExhausted
        } else if self.process_exit_requested {
            RunStopReason::ProcessExit
        } else if !self.scheduler.has_live_threads() {
            RunStopReason::AllThreadsTerminated
        } else if self
            .main_thread_tid
            .and_then(|tid| self.scheduler.thread_state(tid))
            == Some("terminated")
        {
            RunStopReason::MainThreadTerminated
        } else {
            RunStopReason::SchedulerIdle
        });
        Ok(())
    }

    #[allow(dead_code)]
    fn run_native_scheduler_main(&mut self) -> Result<(), VmError> {
        let main_module = self.load()?.clone();
        let entry_module = self
            .entry_module
            .as_ref()
            .cloned()
            .unwrap_or_else(|| main_module.clone());
        let entry_address = self.entry_address.unwrap_or(entry_module.entrypoint);
        let entry_arguments = self.entry_arguments.clone();
        let mut skipped_bases = vec![main_module.base];
        if entry_module.base != main_module.base {
            skipped_bases.push(entry_module.base);
        }
        self.run_loaded_module_initializers(&skipped_bases)?;
        self.run_tls_callbacks(&entry_module, DLL_PROCESS_ATTACH, "entry")?;
        self.prepare_scheduler_main_thread(entry_address, &entry_arguments)?;
        self.complete_process_startup_sequence()?;
        self.log_entry_invoke(&entry_module, entry_address, &entry_arguments)?;
        self.run_unicorn_scheduler_loop()
    }

    fn run_interpreter_scheduler_main(&mut self) -> Result<(), VmError> {
        let main_module = self.load()?.clone();
        let entry_module = self
            .entry_module
            .as_ref()
            .cloned()
            .unwrap_or_else(|| main_module.clone());
        let entry_address = self.entry_address.unwrap_or(entry_module.entrypoint);
        let entry_arguments = self.entry_arguments.clone();
        let mut skipped_bases = vec![main_module.base];
        if entry_module.base != main_module.base {
            skipped_bases.push(entry_module.base);
        }
        self.run_loaded_module_initializers(&skipped_bases)?;
        match self.entry_invocation {
            EntryInvocation::NativeEntrypoint => {
                self.run_tls_callbacks(&entry_module, DLL_PROCESS_ATTACH, "entry")?;
            }
            EntryInvocation::Export => {
                if self.entry_module_requires_attach {
                    self.run_module_initializers(&entry_module, "entry")?;
                } else {
                    self.run_tls_callbacks(&entry_module, DLL_PROCESS_ATTACH, "entry")?;
                }
            }
        }
        self.prepare_scheduler_main_thread(entry_address, &entry_arguments)?;
        self.complete_process_startup_sequence()?;
        self.log_entry_invoke(&entry_module, entry_address, &entry_arguments)?;
        self.run_scheduler_loop()
    }

    #[allow(dead_code)]
    fn prepare_scheduler_main_thread(
        &mut self,
        start_address: u64,
        arguments: &[u64],
    ) -> Result<(), VmError> {
        let main_tid = self
            .main_thread_tid
            .ok_or(VmError::RuntimeInvariant("main thread not initialized"))?;
        let thread = self
            .scheduler
            .thread_snapshot(main_tid)
            .ok_or(VmError::RuntimeInvariant("main thread snapshot missing"))?;
        self.scheduler
            .set_thread_start_address(main_tid, start_address)
            .ok_or(VmError::RuntimeInvariant(
                "failed to set main thread entrypoint",
            ))?;
        self.scheduler
            .set_thread_parameter(main_tid, arguments.first().copied().unwrap_or(0))
            .ok_or(VmError::RuntimeInvariant(
                "failed to set main thread parameter",
            ))?;
        self.scheduler
            .set_thread_exit_address(main_tid, self.native_return_sentinel)
            .ok_or(VmError::RuntimeInvariant(
                "failed to set main thread exit address",
            ))?;
        let stack_top = thread.stack_top;
        let thread_context = crate::runtime::thread_context::ThreadContext {
            teb_base: thread.teb_base,
            stack_base: thread.stack_base,
            stack_limit: thread.stack_limit,
        };
        self.initialize_scheduler_thread_context(main_tid, thread_context, stack_top)?;
        let mut registers = self
            .scheduler
            .thread_snapshot(main_tid)
            .ok_or(VmError::RuntimeInvariant("main thread snapshot missing"))?
            .registers;
        if self.arch.is_x86() {
            let saved_esp = registers
                .get("esp")
                .copied()
                .ok_or(VmError::RuntimeInvariant("main thread ESP missing"))?;
            let mut frame = Vec::with_capacity((arguments.len() + 1) * 4);
            frame.extend_from_slice(&(self.native_return_sentinel as u32).to_le_bytes());
            for value in arguments {
                frame.extend_from_slice(&(*value as u32).to_le_bytes());
            }
            let new_esp = saved_esp
                .checked_sub(frame.len() as u64)
                .ok_or(VmError::RuntimeInvariant("native call stack underflow"))?;
            self.modules.memory_mut().write(new_esp, &frame)?;
            registers.insert("esp".to_string(), new_esp);
            registers.insert("eip".to_string(), start_address);
        } else {
            let saved_rsp = registers
                .get("rsp")
                .copied()
                .ok_or(VmError::RuntimeInvariant("main thread RSP missing"))?;
            let stack_arg_count = arguments.len().saturating_sub(4);
            let frame_size = 0x28 + stack_arg_count * 8;
            let new_rsp = saved_rsp
                .checked_sub(frame_size as u64)
                .ok_or(VmError::RuntimeInvariant("native call stack underflow"))?;
            let mut frame = vec![0u8; frame_size];
            frame[0..8].copy_from_slice(&self.native_return_sentinel.to_le_bytes());
            for (index, value) in arguments.iter().skip(4).enumerate() {
                let offset = 0x28 + index * 8;
                frame[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
            self.modules.memory_mut().write(new_rsp, &frame)?;
            registers.insert("rcx".to_string(), arguments.first().copied().unwrap_or(0));
            registers.insert("rdx".to_string(), arguments.get(1).copied().unwrap_or(0));
            registers.insert("r8".to_string(), arguments.get(2).copied().unwrap_or(0));
            registers.insert("r9".to_string(), arguments.get(3).copied().unwrap_or(0));
            registers.insert("rsp".to_string(), new_rsp);
            registers.insert("rip".to_string(), start_address);
        }
        self.scheduler
            .set_thread_registers(main_tid, registers)
            .ok_or(VmError::RuntimeInvariant(
                "failed to seed main thread entry frame",
            ))?;
        self.scheduler
            .mark_thread_ready(main_tid)
            .ok_or(VmError::RuntimeInvariant("failed to ready main thread"))?;
        self.scheduler
            .switch_to(main_tid, &mut self.process_env)
            .ok_or(VmError::RuntimeInvariant("failed to bind main thread"))?;
        self.sync_native_support_state()?;
        Ok(())
    }

    #[allow(dead_code)]
    fn run_unicorn_scheduler_loop(&mut self) -> Result<(), VmError> {
        let mut remaining = self.remaining_run_budget();
        if remaining == 0 {
            self.stop_reason = Some(RunStopReason::InstructionBudgetExhausted);
            return Ok(());
        }
        while remaining > 0 {
            {
                let _profile = self
                    .runtime_profiler
                    .start_scope("scheduler.poll_blocked_threads");
                self.scheduler
                    .poll_blocked_threads(self.time.current().tick_ms);
            }
            let Some(thread) = self.scheduler.next_ready_thread() else {
                if !self.scheduler.has_live_threads() {
                    break;
                }
                if let Some(next_tick) = self.scheduler.next_wake_tick() {
                    let current_tick = self.time.current().tick_ms;
                    if next_tick > current_tick {
                        self.time.advance(next_tick - current_tick);
                        continue;
                    }
                }
                break;
            };
            self.prepare_remote_shellcode_thread_if_needed(thread.tid)?;
            if self.scheduler.thread_state(thread.tid) != Some("running") {
                continue;
            }
            {
                let _profile = self.runtime_profiler.start_scope("scheduler.switch_to");
                self.scheduler
                    .switch_to(thread.tid, &mut self.process_env)
                    .ok_or(VmError::RuntimeInvariant(
                        "failed to switch scheduler thread",
                    ))?;
            }
            self.sync_native_support_state()?;
            let budget = remaining.min(self.scheduler.time_slice_instructions());
            let before = self.instruction_count;
            {
                let _profile = self
                    .runtime_profiler
                    .start_scope("unicorn.thread_slice_total");
                self.run_unicorn_thread_slice(thread.tid, budget)?;
            }
            let consumed = self.instruction_count.saturating_sub(before).max(1);
            remaining = remaining.saturating_sub(consumed);

            if self.scheduler.thread_state(thread.tid) == Some("terminated")
                && self.started_threads.remove(&thread.tid)
            {
                let _ = self.dispatch_thread_notification(thread.tid, DLL_THREAD_DETACH);
            }
            if Some(thread.tid) == self.main_thread_tid
                && self.scheduler.thread_state(thread.tid) == Some("terminated")
            {
                self.exit_code = self
                    .scheduler
                    .thread_exit_code(thread.tid)
                    .flatten()
                    .or(self.exit_code);
                if self.process_exit_requested || !self.scheduler.has_live_threads() {
                    break;
                }
            }

            self.time.advance(self.scheduler.time_slice_ms());
        }
        self.stop_reason = Some(if remaining == 0 {
            RunStopReason::InstructionBudgetExhausted
        } else if self.process_exit_requested {
            RunStopReason::ProcessExit
        } else if !self.scheduler.has_live_threads() {
            RunStopReason::AllThreadsTerminated
        } else if self
            .main_thread_tid
            .and_then(|tid| self.scheduler.thread_state(tid))
            == Some("terminated")
        {
            RunStopReason::MainThreadTerminated
        } else {
            RunStopReason::SchedulerIdle
        });
        Ok(())
    }

    fn run_native_main(&mut self) -> Result<(), VmError> {
        let main_module = self.load()?.clone();
        let entry_module = self
            .entry_module
            .as_ref()
            .cloned()
            .unwrap_or_else(|| main_module.clone());
        let entry_address = self.entry_address.unwrap_or(entry_module.entrypoint);
        let entry_arguments = self.entry_arguments.clone();
        let mut skipped_bases = vec![main_module.base];
        if entry_module.base != main_module.base {
            skipped_bases.push(entry_module.base);
        }
        self.run_loaded_module_initializers(&skipped_bases)?;
        match self.entry_invocation {
            EntryInvocation::NativeEntrypoint => {
                self.run_tls_callbacks(&entry_module, DLL_PROCESS_ATTACH, "entry")?;
            }
            EntryInvocation::Export => {
                if self.entry_module_requires_attach {
                    self.run_module_initializers(&entry_module, "entry")?;
                } else {
                    self.run_tls_callbacks(&entry_module, DLL_PROCESS_ATTACH, "entry")?;
                }
            }
        }
        self.prepare_scheduler_main_thread(entry_address, &entry_arguments)?;
        self.complete_process_startup_sequence()?;
        self.log_entry_invoke(&entry_module, entry_address, &entry_arguments)?;
        self.force_native_return = false;
        if self.arch.is_x64() {
            return self.run_unicorn_scheduler_loop();
        }
        let retval = self.call_native_with_entry_frame(entry_address, &entry_arguments)? as u32;
        if self.stop_reason == Some(RunStopReason::InstructionBudgetExhausted) {
            return Ok(());
        }
        let main_thread_state = self
            .main_thread_tid
            .and_then(|tid| self.scheduler.thread_state(tid));
        if matches!(main_thread_state, Some("waiting" | "sleeping" | "ready")) {
            return if self.unicorn.is_some() {
                self.run_unicorn_scheduler_loop()
            } else {
                self.run_scheduler_loop()
            };
        }
        if self.exit_code.is_none() {
            self.exit_code = Some(retval);
        }
        if let Some(main_tid) = self.main_thread_tid {
            let _ = self.scheduler.switch_to(main_tid, &mut self.process_env);
            let _ = self.terminate_current_thread(self.exit_code.unwrap_or(retval));
        }
        if self.process_exit_requested || !self.scheduler.has_live_threads() {
            self.stop_reason = Some(if self.process_exit_requested {
                RunStopReason::ProcessExit
            } else {
                RunStopReason::AllThreadsTerminated
            });
            return Ok(());
        }
        self.run_unicorn_scheduler_loop()
    }
}

impl Drop for VirtualExecutionEngine {
    fn drop(&mut self) {
        self.close_unicorn_session();
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        format_writeback_error_detail, writeback_range_chunks, RunStopReason,
        VirtualExecutionEngine,
    };
    use crate::config::load_config;
    use crate::memory::manager::PAGE_SIZE;
    use crate::runtime::scheduler::{WAIT_ABANDONED_0, WAIT_OBJECT_0, WAIT_TIMEOUT};

    #[test]
    fn writeback_range_chunks_split_on_page_boundaries() {
        assert_eq!(
            writeback_range_chunks(PAGE_SIZE - 0x10, 0x40),
            vec![(PAGE_SIZE - 0x10, 0x10), (PAGE_SIZE, 0x30),]
        );
    }

    #[test]
    fn writeback_error_detail_includes_requested_range_failed_chunk_and_pc() {
        let detail = format_writeback_error_detail(
            "uc_mem_read: Invalid memory read (UC_ERR_READ_UNMAPPED)",
            0x1234,
            0x2200,
            0x2000,
            0x1000,
            Some(0x40269D),
        );
        assert!(detail.contains("write_range=0x1234+0x2200"));
        assert!(detail.contains("failed_chunk=0x2000+0x1000"));
        assert!(detail.contains("flush_pc=0x40269D"));
    }

    #[test]
    fn unicorn_scheduler_continues_ready_worker_after_main_thread_terminates() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../configs/sample_42c4b1eaeba9de5a873970687b4abc34_trace.json");
        let config = load_config(config_path).unwrap();
        let mut engine = VirtualExecutionEngine::new(config).unwrap();
        engine.load().unwrap();

        let worker_code = engine.allocate_executable_test_page(0x6F00_0000).unwrap();
        engine
            .write_test_bytes(worker_code, &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3])
            .unwrap();
        let worker_handle = engine.create_runtime_thread(worker_code, 0, 0, 0).unwrap() as u32;
        let worker_tid = engine
            .scheduler()
            .thread_tid_for_handle(worker_handle)
            .unwrap();
        let main_tid = engine.main_thread_tid.unwrap();

        engine
            .scheduler
            .switch_to(main_tid, &mut engine.process_env)
            .unwrap();
        assert!(engine.terminate_current_thread(1));
        engine.exit_code = Some(1);
        engine.stop_reason = None;
        engine.process_exit_requested = false;

        engine.run_unicorn_scheduler_loop().unwrap();

        assert_eq!(
            engine.scheduler().thread_state(worker_tid),
            Some("terminated")
        );
        assert_eq!(
            engine.scheduler().thread_exit_code(worker_tid),
            Some(Some(0x2A))
        );
        assert_eq!(
            engine.stop_reason,
            Some(RunStopReason::AllThreadsTerminated)
        );
    }

    #[test]
    fn wait_for_single_object_on_thread_handle_resumes_after_worker_exit() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
        let config = load_config(config_path).unwrap();
        let mut engine = VirtualExecutionEngine::new(config).unwrap();
        engine.load().unwrap();

        let worker_code = engine.allocate_executable_test_page(0x6F10_0000).unwrap();
        engine.write_test_bytes(worker_code, &[0xC3]).unwrap();
        let worker_handle = engine.create_runtime_thread(worker_code, 0, 0, 0).unwrap() as u32;
        let worker_tid = engine
            .scheduler()
            .thread_tid_for_handle(worker_handle)
            .unwrap();
        let main_tid = engine.main_thread_tid.unwrap();
        let wait = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");

        engine
            .scheduler
            .switch_to(main_tid, &mut engine.process_env)
            .unwrap();
        assert_eq!(
            engine
                .dispatch_bound_stub(wait, &[worker_handle as u64, u32::MAX as u64])
                .unwrap(),
            WAIT_TIMEOUT as u64
        );
        assert_eq!(engine.scheduler().thread_state(main_tid), Some("waiting"));

        engine
            .scheduler
            .switch_to(worker_tid, &mut engine.process_env)
            .unwrap();
        assert!(engine.terminate_current_thread(7));

        let main_thread = engine.scheduler().thread_snapshot(main_tid).unwrap();
        assert_eq!(main_thread.state, "ready");
        assert_eq!(main_thread.wait_result, Some(WAIT_OBJECT_0));

        engine
            .scheduler
            .switch_to(main_tid, &mut engine.process_env)
            .unwrap();
        assert_eq!(
            engine
                .dispatch_bound_stub(wait, &[worker_handle as u64, u32::MAX as u64])
                .unwrap(),
            WAIT_OBJECT_0 as u64
        );
    }

    #[test]
    fn wait_for_single_object_on_abandoned_mutex_returns_wait_abandoned() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
        let config = load_config(config_path).unwrap();
        let mut engine = VirtualExecutionEngine::new(config).unwrap();
        engine.load().unwrap();

        let worker_code = engine.allocate_executable_test_page(0x6F20_0000).unwrap();
        engine.write_test_bytes(worker_code, &[0xC3]).unwrap();
        let worker_handle = engine.create_runtime_thread(worker_code, 0, 0, 0).unwrap() as u32;
        let worker_tid = engine
            .scheduler()
            .thread_tid_for_handle(worker_handle)
            .unwrap();
        let main_tid = engine.main_thread_tid.unwrap();
        let create_mutex = engine.bind_hook_for_test("kernel32.dll", "CreateMutexW");
        let wait = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");

        engine
            .scheduler
            .switch_to(worker_tid, &mut engine.process_env)
            .unwrap();
        let mutex = engine
            .dispatch_bound_stub(create_mutex, &[0, 1, 0])
            .unwrap() as u32;
        assert_eq!(
            engine
                .dispatch_bound_stub(wait, &[mutex as u64, u32::MAX as u64])
                .unwrap(),
            WAIT_OBJECT_0 as u64
        );
        assert!(engine.terminate_current_thread(9));

        engine
            .scheduler
            .switch_to(main_tid, &mut engine.process_env)
            .unwrap();
        assert_eq!(
            engine
                .dispatch_bound_stub(wait, &[mutex as u64, 0])
                .unwrap(),
            WAIT_ABANDONED_0 as u64
        );
    }

    #[test]
    fn get_message_waits_for_timer_due_before_returning_wm_timer() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
        let config = load_config(config_path).unwrap();
        let mut engine = VirtualExecutionEngine::new(config).unwrap();
        engine.load().unwrap();

        let main_tid = engine.main_thread_tid.unwrap();
        engine
            .scheduler
            .switch_to(main_tid, &mut engine.process_env)
            .unwrap();
        let msg = engine
            .modules
            .memory_mut()
            .reserve(0x1000, Some(0x6F30_0000), "user32:test_msg", true)
            .unwrap();

        assert_eq!(
            engine.user32_register_timer(0x1234, 0x81, 5, 0).unwrap(),
            0x81
        );
        assert_eq!(engine.user32_state.synthetic_timer_messages, 0);

        assert_eq!(engine.user32_get_message(msg, 0, 0, 0).unwrap(), 0);
        let sleeping_thread = engine.scheduler().thread_snapshot(main_tid).unwrap();
        assert_eq!(sleeping_thread.state, "sleeping");
        assert!(sleeping_thread.wake_tick >= engine.time.current().tick_ms + 5);
        assert_eq!(engine.user32_state.synthetic_timer_messages, 0);

        engine.handle_requested_thread_yield();
        engine.thread_yield_requested = false;
        engine.defer_api_return = false;
        engine
            .scheduler
            .switch_to(main_tid, &mut engine.process_env)
            .unwrap();

        assert_eq!(engine.user32_get_message(msg, 0, 0, 0).unwrap(), 1);
        let hwnd = engine.read_pointer_value(msg).unwrap();
        let message = if engine.arch.is_x86() {
            engine.read_u32(msg + 4).unwrap()
        } else {
            engine.read_u32(msg + 8).unwrap()
        };
        let w_param = if engine.arch.is_x86() {
            engine.read_u32(msg + 8).unwrap() as u64
        } else {
            engine.read_pointer_value(msg + 16).unwrap()
        };
        let l_param = if engine.arch.is_x86() {
            engine.read_u32(msg + 12).unwrap() as u64
        } else {
            engine.read_pointer_value(msg + 24).unwrap()
        };
        assert_eq!(hwnd, 0x1234);
        assert_eq!(message, 0x0113);
        assert_eq!(w_param, 0x81);
        assert_eq!(l_param, 0);
        assert_eq!(engine.user32_state.synthetic_timer_messages, 1);
    }

    #[test]
    fn dispatch_message_invokes_x86_timerproc_callback() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
        let config = load_config(config_path).unwrap();
        let mut engine = VirtualExecutionEngine::new(config).unwrap();
        engine.load().unwrap();

        assert!(engine.arch.is_x86());

        let main_tid = engine.main_thread_tid.unwrap();
        engine
            .scheduler
            .switch_to(main_tid, &mut engine.process_env)
            .unwrap();
        let msg = engine
            .modules
            .memory_mut()
            .reserve(0x1000, Some(0x6F31_0000), "user32:test_msg", true)
            .unwrap();
        let timerproc = engine.allocate_executable_test_page(0x6F40_0000).unwrap();
        engine
            .write_test_bytes(timerproc, &[0xB8, 0x44, 0x33, 0x22, 0x11, 0xC2, 0x10, 0x00])
            .unwrap();

        assert_eq!(
            engine
                .user32_register_timer(0x4321, 0x99, 5, timerproc)
                .unwrap(),
            0x99
        );
        assert_eq!(engine.user32_get_message(msg, 0, 0, 0).unwrap(), 0);

        engine.handle_requested_thread_yield();
        engine.thread_yield_requested = false;
        engine.defer_api_return = false;
        engine
            .scheduler
            .switch_to(main_tid, &mut engine.process_env)
            .unwrap();

        assert_eq!(engine.user32_get_message(msg, 0, 0, 0).unwrap(), 1);
        let message = engine.read_u32(msg + 4).unwrap();
        let w_param = engine.read_u32(msg + 8).unwrap() as u64;
        let l_param = engine.read_u32(msg + 12).unwrap() as u64;
        assert_eq!(message, 0x0113);
        assert_eq!(w_param, 0x99);
        assert_eq!(l_param, timerproc);
        assert_eq!(engine.user32_dispatch_message(msg).unwrap(), 0x1122_3344);
    }

    #[test]
    fn send_message_invokes_registered_wndproc_x86() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
        let config = load_config(config_path).unwrap();
        let mut engine = VirtualExecutionEngine::new(config).unwrap();
        engine.load().unwrap();

        assert!(engine.arch.is_x86());

        let main_tid = engine.main_thread_tid.unwrap();
        engine
            .scheduler
            .switch_to(main_tid, &mut engine.process_env)
            .unwrap();

        let class_name = engine
            .modules
            .memory_mut()
            .reserve(0x1000, Some(0x6F50_0000), "user32:test_class_name", true)
            .unwrap();
        let window_title = engine
            .modules
            .memory_mut()
            .reserve(0x1000, Some(0x6F51_0000), "user32:test_window_title", true)
            .unwrap();
        let class_def = engine
            .modules
            .memory_mut()
            .reserve(0x1000, Some(0x6F52_0000), "user32:test_class_def", true)
            .unwrap();
        engine
            .modules
            .memory_mut()
            .write(class_def, &vec![0u8; 0x100])
            .unwrap();
        engine
            .write_wide_string_to_memory(class_name, 64, "UnitTestWindow")
            .unwrap();
        engine
            .write_wide_string_to_memory(window_title, 64, "UnitTestWindow")
            .unwrap();

        let wnd_proc = engine.allocate_executable_test_page(0x6F60_0000).unwrap();
        engine
            .write_test_bytes(wnd_proc, &[0xB8, 0x78, 0x56, 0x34, 0x12, 0xC2, 0x10, 0x00])
            .unwrap();

        engine.write_u32(class_def, 48).unwrap();
        engine.write_pointer_value(class_def + 8, wnd_proc).unwrap();
        engine
            .write_pointer_value(class_def + 40, class_name)
            .unwrap();

        let register_class = engine.bind_hook_for_test("user32.dll", "RegisterClassExW");
        let create_window = engine.bind_hook_for_test("user32.dll", "CreateWindowExW");
        let send_message = engine.bind_hook_for_test("user32.dll", "SendMessageW");

        let atom = engine
            .dispatch_bound_stub(register_class, &[class_def])
            .unwrap();
        assert_ne!(atom, 0);

        let hwnd = engine
            .dispatch_bound_stub(
                create_window,
                &[0, class_name, window_title, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            )
            .unwrap();
        assert_ne!(hwnd, 0);
        assert_eq!(engine.user32_window_proc(hwnd as u32), wnd_proc);

        assert_eq!(
            engine
                .dispatch_bound_stub(send_message, &[hwnd, 0x4242, 1, 2])
                .unwrap(),
            0x1234_5678
        );
    }

    #[test]
    fn send_message_invokes_registered_wndproc_x64_from_native_context() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../configs/sample_42c4b1eaeba9de5a873970687b4abc34_trace.json");
        let config = load_config(config_path).unwrap();
        let mut engine = VirtualExecutionEngine::new(config).unwrap();
        engine.load().unwrap();

        assert!(engine.arch.is_x64());

        let main_tid = engine.main_thread_tid.unwrap();
        engine
            .scheduler
            .switch_to(main_tid, &mut engine.process_env)
            .unwrap();

        let class_name = engine
            .modules
            .memory_mut()
            .reserve(0x1000, Some(0x6F70_0000), "user32:test_class_name64", true)
            .unwrap();
        let window_title = engine
            .modules
            .memory_mut()
            .reserve(
                0x1000,
                Some(0x6F71_0000),
                "user32:test_window_title64",
                true,
            )
            .unwrap();
        let class_def = engine
            .modules
            .memory_mut()
            .reserve(0x1000, Some(0x6F72_0000), "user32:test_class_def64", true)
            .unwrap();
        engine
            .modules
            .memory_mut()
            .write(class_def, &vec![0u8; 0x100])
            .unwrap();
        engine
            .write_wide_string_to_memory(class_name, 64, "UnitTestWindow64")
            .unwrap();
        engine
            .write_wide_string_to_memory(window_title, 64, "UnitTestWindow64")
            .unwrap();

        let wnd_proc = engine.allocate_executable_test_page(0x6F80_0000).unwrap();
        let wnd_proc_result = 0x1122_3344_5566_7788u64;
        let mut wnd_proc_bytes = vec![0x48, 0xB8];
        wnd_proc_bytes.extend_from_slice(&wnd_proc_result.to_le_bytes());
        wnd_proc_bytes.push(0xC3);
        engine.write_test_bytes(wnd_proc, &wnd_proc_bytes).unwrap();

        engine.write_u32(class_def, 80).unwrap();
        engine.write_pointer_value(class_def + 8, wnd_proc).unwrap();
        engine
            .write_pointer_value(class_def + 64, class_name)
            .unwrap();

        let register_class = engine.bind_hook_for_test("user32.dll", "RegisterClassExW");
        let create_window = engine.bind_hook_for_test("user32.dll", "CreateWindowExW");
        let send_message = engine.bind_hook_for_test("user32.dll", "SendMessageW");

        let atom = engine
            .dispatch_bound_stub(register_class, &[class_def])
            .unwrap();
        assert_ne!(atom, 0);

        let hwnd = engine
            .dispatch_bound_stub(
                create_window,
                &[0, class_name, window_title, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            )
            .unwrap();
        assert_ne!(hwnd, 0);
        assert_eq!(engine.user32_window_proc(hwnd as u32), wnd_proc);

        let caller = engine.allocate_executable_test_page(0x6F81_0000).unwrap();
        let mut caller_bytes = Vec::new();
        caller_bytes.extend_from_slice(&[0x48, 0xB9]);
        caller_bytes.extend_from_slice(&hwnd.to_le_bytes());
        caller_bytes.extend_from_slice(&[0x48, 0xBA]);
        caller_bytes.extend_from_slice(&(0x2B11u64).to_le_bytes());
        caller_bytes.extend_from_slice(&[0x49, 0xB8]);
        caller_bytes.extend_from_slice(&(0xAA55u64).to_le_bytes());
        caller_bytes.extend_from_slice(&[0x49, 0xB9]);
        caller_bytes.extend_from_slice(&(0x55AA_1234u64).to_le_bytes());
        caller_bytes.extend_from_slice(&[0x48, 0xB8]);
        caller_bytes.extend_from_slice(&send_message.to_le_bytes());
        caller_bytes.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD0]);
        caller_bytes.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
        engine.write_test_bytes(caller, &caller_bytes).unwrap();

        assert_eq!(
            engine.call_native_for_test(caller, &[]).unwrap(),
            wnd_proc_result
        );
        assert!(engine.pending_user32_sendmessage_callbacks.is_empty());
    }
}

thread_local! {
    static ACTIVE_UNICORN_CONTEXT: Cell<*mut UnicornRunContext> = const { Cell::new(std::ptr::null_mut()) };
}

fn unicorn_context_active() -> bool {
    ACTIVE_UNICORN_CONTEXT.with(|slot| !slot.get().is_null())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnicornFaultAccess {
    Read,
    Write,
    Execute,
}

impl UnicornFaultAccess {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnicornFault {
    access: UnicornFaultAccess,
    address: u64,
    size: usize,
    pc: u64,
}

struct UnicornRunContext {
    engine: *mut VirtualExecutionEngine,
    api: *const UnicornApi,
    uc: *mut UcEngine,
    callback_error: Option<VmError>,
    pending_fault: Option<UnicornFault>,
    pending_writes: Vec<(u64, usize)>,
    suppress_mem_write_hook: bool,
    last_native_block: Option<(u64, u32)>,
    recent_blocks: VecDeque<NativeBlockSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeCallRunMode {
    Standalone,
    EntryFrame,
}

#[derive(Debug, Clone)]
struct NativeBlockSnapshot {
    pc: u64,
    size: u32,
    registers: BTreeMap<String, u64>,
    stack_words: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoopValueDelta {
    before: u64,
    after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct LoopStateDelta {
    registers: BTreeMap<String, LoopValueDelta>,
    stack_words: BTreeMap<String, LoopValueDelta>,
}

impl LoopStateDelta {
    fn is_empty(&self) -> bool {
        self.registers.is_empty() && self.stack_words.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoopPhaseDelta {
    phase: usize,
    pc: u64,
    size: u32,
    state_delta: LoopStateDelta,
}

impl LoopPhaseDelta {
    fn change_count(&self) -> usize {
        self.state_delta.registers.len() + self.state_delta.stack_words.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoopPhaseSummary {
    phase: usize,
    pc: u64,
    size: u32,
    changed_registers: Vec<String>,
    changed_stack_words: Vec<String>,
}

impl LoopPhaseSummary {
    fn change_count(&self) -> usize {
        self.changed_registers.len() + self.changed_stack_words.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeLoopSnapshot {
    blocks: Vec<(u64, u32)>,
    observed_blocks: Vec<(u64, u32)>,
    period: usize,
    repeats: u64,
    state_delta: Option<LoopStateDelta>,
    phase_summaries: Vec<LoopPhaseSummary>,
    phase_deltas: Vec<LoopPhaseDelta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveNativeLoop {
    blocks: Vec<(u64, u32)>,
    observed_blocks: Vec<(u64, u32)>,
    period: usize,
    repeats: u64,
    state_delta: Option<LoopStateDelta>,
    phase_summaries: Vec<LoopPhaseSummary>,
    phase_deltas: Vec<LoopPhaseDelta>,
    next_emit_repeats: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeTraceUpdate {
    should_log_progress: bool,
    loop_snapshot: Option<NativeLoopSnapshot>,
}

#[derive(Debug)]
struct NativeTraceState {
    total_blocks: u64,
    block_hits: BTreeMap<(u64, u32), u64>,
    recent_sequence: VecDeque<(u64, u32)>,
    recent_snapshots: VecDeque<NativeBlockSnapshot>,
    active_loop: Option<ActiveNativeLoop>,
    next_progress_instruction: u64,
}

impl NativeTraceState {
    fn reset(&mut self) {
        self.total_blocks = 0;
        self.block_hits.clear();
        self.recent_sequence.clear();
        self.recent_snapshots.clear();
        self.active_loop = None;
        self.next_progress_instruction = NATIVE_PROGRESS_INTERVAL_INSTRUCTIONS;
    }

    fn record_block(
        &mut self,
        instruction_count: u64,
        pc: u64,
        size: u32,
        snapshot: Option<&NativeBlockSnapshot>,
    ) -> NativeTraceUpdate {
        self.total_blocks = self.total_blocks.saturating_add(1);
        *self.block_hits.entry((pc, size)).or_insert(0) += 1;
        self.recent_sequence.push_back((pc, size));
        if self.recent_sequence.len() > NATIVE_LOOP_HISTORY_BLOCKS {
            self.recent_sequence.pop_front();
        }
        if let Some(snapshot) = snapshot {
            self.recent_snapshots.push_back(snapshot.clone());
            if self.recent_snapshots.len() > NATIVE_LOOP_HISTORY_BLOCKS {
                self.recent_snapshots.pop_front();
            }
        }
        let loop_snapshot = self.update_loop_detection();
        let should_log_progress = if instruction_count < self.next_progress_instruction {
            false
        } else {
            self.next_progress_instruction =
                instruction_count.saturating_add(NATIVE_PROGRESS_INTERVAL_INSTRUCTIONS);
            true
        };
        NativeTraceUpdate {
            should_log_progress,
            loop_snapshot,
        }
    }

    fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    fn unique_blocks(&self) -> usize {
        self.block_hits.len()
    }

    fn active_loop(&self) -> Option<NativeLoopSnapshot> {
        self.active_loop.as_ref().map(|active| NativeLoopSnapshot {
            blocks: active.blocks.clone(),
            observed_blocks: active.observed_blocks.clone(),
            period: active.period,
            repeats: active.repeats,
            state_delta: active.state_delta.clone(),
            phase_summaries: active.phase_summaries.clone(),
            phase_deltas: active.phase_deltas.clone(),
        })
    }

    fn top_blocks(&self, limit: usize) -> Vec<((u64, u32), u64)> {
        let mut blocks = self
            .block_hits
            .iter()
            .map(|(&(pc, size), &hits)| ((pc, size), hits))
            .collect::<Vec<_>>();
        blocks.sort_by(|left, right| {
            right
                .1
                .cmp(&left.1)
                .then_with(|| left.0 .0.cmp(&right.0 .0))
                .then_with(|| left.0 .1.cmp(&right.0 .1))
        });
        blocks.truncate(limit);
        blocks
    }

    fn update_loop_detection(&mut self) -> Option<NativeLoopSnapshot> {
        let Some(detected) = self.detect_repeating_loop() else {
            self.active_loop = None;
            return None;
        };

        match &mut self.active_loop {
            Some(active)
                if active.period == detected.period && active.blocks == detected.blocks =>
            {
                active.repeats = detected.repeats;
                active.observed_blocks = detected.observed_blocks.clone();
                active.state_delta = detected.state_delta.clone();
                active.phase_summaries = detected.phase_summaries.clone();
                active.phase_deltas = detected.phase_deltas.clone();
                if active.repeats < active.next_emit_repeats {
                    return None;
                }
                while active.next_emit_repeats <= active.repeats {
                    active.next_emit_repeats = active.next_emit_repeats.saturating_mul(2);
                }
                Some(NativeLoopSnapshot {
                    blocks: active.blocks.clone(),
                    observed_blocks: active.observed_blocks.clone(),
                    period: active.period,
                    repeats: active.repeats,
                    state_delta: active.state_delta.clone(),
                    phase_summaries: active.phase_summaries.clone(),
                    phase_deltas: active.phase_deltas.clone(),
                })
            }
            _ => {
                self.active_loop = Some(ActiveNativeLoop {
                    blocks: detected.blocks.clone(),
                    observed_blocks: detected.observed_blocks.clone(),
                    period: detected.period,
                    repeats: detected.repeats,
                    state_delta: detected.state_delta.clone(),
                    phase_summaries: detected.phase_summaries.clone(),
                    phase_deltas: detected.phase_deltas.clone(),
                    next_emit_repeats: detected.repeats.saturating_mul(2),
                });
                Some(detected)
            }
        }
    }

    fn detect_repeating_loop(&mut self) -> Option<NativeLoopSnapshot> {
        let sequence = self.recent_sequence.make_contiguous();
        if sequence.len() < NATIVE_LOOP_MIN_PERIOD_BLOCKS * NATIVE_LOOP_MIN_REPEATS as usize {
            return None;
        }
        let max_period =
            NATIVE_LOOP_MAX_PERIOD_BLOCKS.min(sequence.len() / NATIVE_LOOP_MIN_REPEATS as usize);
        for period in NATIVE_LOOP_MIN_PERIOD_BLOCKS..=max_period {
            let pattern_start = sequence.len().saturating_sub(period);
            let pattern = &sequence[pattern_start..];
            let mut repeats = 1u64;
            while sequence.len() >= (repeats as usize + 1) * period {
                let start = sequence.len() - (repeats as usize + 1) * period;
                let end = start + period;
                if &sequence[start..end] != pattern {
                    break;
                }
                repeats = repeats.saturating_add(1);
            }
            if repeats >= NATIVE_LOOP_MIN_REPEATS {
                let observed_blocks = pattern.to_vec();
                return Some(NativeLoopSnapshot {
                    blocks: Self::canonicalize_loop_blocks(pattern),
                    observed_blocks: observed_blocks.clone(),
                    period,
                    repeats,
                    state_delta: self.current_loop_state_delta(&observed_blocks),
                    phase_summaries: self.current_loop_phase_summaries(&observed_blocks),
                    phase_deltas: self.current_loop_phase_deltas(&observed_blocks),
                });
            }
        }
        None
    }

    fn current_loop_state_delta(&self, observed_blocks: &[(u64, u32)]) -> Option<LoopStateDelta> {
        let pairs = self.current_loop_phase_pairs(observed_blocks)?;
        let (before, after) = pairs.first().copied()?;
        let state_delta = LoopStateDelta {
            registers: Self::diff_named_values(&before.registers, &after.registers),
            stack_words: Self::diff_named_values(&before.stack_words, &after.stack_words),
        };
        if state_delta.is_empty() {
            None
        } else {
            Some(state_delta)
        }
    }

    fn diff_named_values(
        before: &BTreeMap<String, u64>,
        after: &BTreeMap<String, u64>,
    ) -> BTreeMap<String, LoopValueDelta> {
        let mut deltas = BTreeMap::new();
        for key in before.keys().chain(after.keys()) {
            let Some(before_value) = before.get(key).copied() else {
                continue;
            };
            let Some(after_value) = after.get(key).copied() else {
                continue;
            };
            if before_value == after_value {
                continue;
            }
            deltas.insert(
                key.clone(),
                LoopValueDelta {
                    before: before_value,
                    after: after_value,
                },
            );
        }
        deltas
    }

    fn current_loop_phase_pairs<'a>(
        &'a self,
        observed_blocks: &[(u64, u32)],
    ) -> Option<Vec<(&'a NativeBlockSnapshot, &'a NativeBlockSnapshot)>> {
        let period = observed_blocks.len();
        if period == 0 || self.recent_snapshots.len() < period * 2 {
            return None;
        }
        let snapshots = self.recent_snapshots.iter().collect::<Vec<_>>();
        let previous = &snapshots[snapshots.len() - period * 2..snapshots.len() - period];
        let current = &snapshots[snapshots.len() - period..];
        if previous
            .iter()
            .map(|snapshot| (snapshot.pc, snapshot.size))
            .ne(observed_blocks.iter().copied())
        {
            return None;
        }
        if current
            .iter()
            .map(|snapshot| (snapshot.pc, snapshot.size))
            .ne(observed_blocks.iter().copied())
        {
            return None;
        }
        Some(
            previous
                .iter()
                .zip(current.iter())
                .map(|(before, after)| (*before, *after))
                .collect(),
        )
    }

    fn current_loop_phase_summaries(
        &self,
        observed_blocks: &[(u64, u32)],
    ) -> Vec<LoopPhaseSummary> {
        let Some(pairs) = self.current_loop_phase_pairs(observed_blocks) else {
            return Vec::new();
        };
        pairs
            .into_iter()
            .enumerate()
            .map(|(phase, (before, after))| {
                let changed_registers =
                    Self::diff_named_values(&before.registers, &after.registers)
                        .into_keys()
                        .collect();
                let changed_stack_words =
                    Self::diff_named_values(&before.stack_words, &after.stack_words)
                        .into_keys()
                        .collect();
                LoopPhaseSummary {
                    phase,
                    pc: after.pc,
                    size: after.size,
                    changed_registers,
                    changed_stack_words,
                }
            })
            .collect()
    }

    fn current_loop_phase_deltas(&self, observed_blocks: &[(u64, u32)]) -> Vec<LoopPhaseDelta> {
        let Some(pairs) = self.current_loop_phase_pairs(observed_blocks) else {
            return Vec::new();
        };
        let mut phase_deltas = pairs
            .into_iter()
            .enumerate()
            .filter_map(|(phase, (before, after))| {
                let state_delta = LoopStateDelta {
                    registers: Self::diff_named_values(&before.registers, &after.registers),
                    stack_words: Self::diff_named_values(&before.stack_words, &after.stack_words),
                };
                if state_delta.is_empty() {
                    return None;
                }
                Some(LoopPhaseDelta {
                    phase,
                    pc: after.pc,
                    size: after.size,
                    state_delta,
                })
            })
            .collect::<Vec<_>>();

        phase_deltas.sort_by(|left, right| {
            right
                .change_count()
                .cmp(&left.change_count())
                .then_with(|| left.phase.cmp(&right.phase))
        });
        phase_deltas.truncate(NATIVE_LOOP_PHASE_DELTA_LIMIT);
        phase_deltas
    }

    fn canonicalize_loop_blocks(blocks: &[(u64, u32)]) -> Vec<(u64, u32)> {
        if blocks.len() <= 1 {
            return blocks.to_vec();
        }
        let mut best = blocks.to_vec();
        for rotation in 1..blocks.len() {
            let mut candidate = Vec::with_capacity(blocks.len());
            candidate.extend_from_slice(&blocks[rotation..]);
            candidate.extend_from_slice(&blocks[..rotation]);
            if candidate < best {
                best = candidate;
            }
        }
        best
    }
}

impl Default for NativeTraceState {
    fn default() -> Self {
        Self {
            total_blocks: 0,
            block_hits: BTreeMap::new(),
            recent_sequence: VecDeque::new(),
            recent_snapshots: VecDeque::new(),
            active_loop: None,
            next_progress_instruction: NATIVE_PROGRESS_INTERVAL_INSTRUCTIONS,
        }
    }
}

fn flush_unicorn_pending_writes(
    state: &mut UnicornRunContext,
    uc: *mut UcEngine,
) -> Result<(), VmError> {
    if state.pending_writes.is_empty() {
        return Ok(());
    }
    let api = unsafe { &*state.api };
    let engine = unsafe { &mut *state.engine };
    let _profile = engine
        .runtime_profiler
        .start_scope("unicorn.flush_pending_writes");
    let pending = std::mem::take(&mut state.pending_writes);
    state.suppress_mem_write_hook = true;
    let flush_pc = if engine.arch.is_x86() {
        unsafe { api.reg_read_raw(uc, UC_X86_REG_EIP) }.ok()
    } else {
        unsafe { api.reg_read_raw(uc, UC_X86_REG_RIP) }.ok()
    };
    let result = (|| -> Result<(), VmError> {
        for (address, size) in pending {
            for (chunk_address, chunk_size) in writeback_range_chunks(address, size) {
                let bytes = unsafe { api.mem_read_raw(uc, chunk_address, chunk_size) }.map_err(
                    |detail| VmError::NativeExecution {
                        op: "uc_mem_read(writeback)",
                        detail: format_writeback_error_detail(
                            &detail,
                            address,
                            size,
                            chunk_address,
                            chunk_size,
                            flush_pc,
                        ),
                    },
                )?;
                if engine
                    .modules
                    .memory()
                    .find_region(chunk_address, 1)
                    .map(|region| region.perms & PROT_EXEC != 0)
                    .unwrap_or(false)
                {
                    let preview_len = bytes.len().min(16);
                    engine.log_native_code_write(
                        chunk_address,
                        chunk_size,
                        &bytes[..preview_len],
                    )?;
                }
                engine
                    .modules
                    .memory_mut()
                    .write_mirror(chunk_address, &bytes)?;
                engine.propagate_file_mapping_write(
                    engine.current_process_space_key(),
                    chunk_address,
                    &bytes,
                )?;
            }
        }
        Ok(())
    })();
    state.suppress_mem_write_hook = false;
    result
}

fn writeback_range_chunks(address: u64, size: usize) -> Vec<(u64, usize)> {
    if size == 0 {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let mut cursor = address;
    let end = address.saturating_add(size as u64);
    while cursor < end {
        let next_page = ((cursor & !(PAGE_SIZE - 1)).saturating_add(PAGE_SIZE)).min(end);
        let chunk_size = next_page.saturating_sub(cursor) as usize;
        chunks.push((cursor, chunk_size));
        cursor = next_page;
    }
    chunks
}

fn format_writeback_error_detail(
    detail: &str,
    requested_address: u64,
    requested_size: usize,
    chunk_address: u64,
    chunk_size: usize,
    pc: Option<u64>,
) -> String {
    let mut rendered = format!(
        "{detail}; write_range=0x{requested_address:X}+0x{requested_size:X}; failed_chunk=0x{chunk_address:X}+0x{chunk_size:X}"
    );
    if let Some(pc) = pc {
        rendered.push_str(&format!("; flush_pc=0x{pc:X}"));
    }
    rendered
}

unsafe extern "C" fn unicorn_code_hook(
    uc: *mut UcEngine,
    address: u64,
    _size: u32,
    _user_data: *mut c_void,
) {
    let state_ptr = ACTIVE_UNICORN_CONTEXT.with(|slot| slot.get());
    if state_ptr.is_null() {
        return;
    }
    let state = &mut *state_ptr;
    if state.callback_error.is_some() {
        return;
    }
    if let Err(error) = flush_unicorn_pending_writes(state, uc) {
        state.callback_error = Some(error);
        let api = &*state.api;
        let _ = unsafe { api.emu_stop_raw(uc) };
        return;
    }
    let engine = &mut *state.engine;
    let api = &*state.api;
    engine.record_instruction_retired();
    if address == engine.native_return_sentinel {
        let _ = unsafe { api.emu_stop_raw(uc) };
        return;
    }
    if address & 0xF != 0 {
        return;
    }

    if let Some(bound) = engine.hooks.bound_lookup(address) {
        if let Some(definition) = bound.definition.cloned() {
            let result =
                (|| -> Result<(), VmError> {
                    let (return_address, args, stack_pointer, saved_x86_nonvolatile) =
                        if engine.arch.is_x86() {
                            let esp = unsafe { api.reg_read_raw(uc, UC_X86_REG_ESP) }.map_err(
                                |detail| VmError::NativeExecution {
                                    op: "uc_reg_read(esp)",
                                    detail,
                                },
                            )?;
                            let frame_size = 4 + definition.argc * 4;
                            let stack = unsafe { api.mem_read_raw(uc, esp, frame_size) }.map_err(
                                |detail| VmError::NativeExecution {
                                    op: "uc_mem_read(stack)",
                                    detail,
                                },
                            )?;
                            let return_address =
                                u32::from_le_bytes(stack[0..4].try_into().unwrap()) as u64;
                            let mut args = Vec::with_capacity(definition.argc);
                            for chunk in stack[4..].chunks_exact(4) {
                                args.push(u32::from_le_bytes(chunk.try_into().unwrap()) as u64);
                            }
                            let ebx = unsafe { api.reg_read_raw(uc, UC_X86_REG_EBX) }.map_err(
                                |detail| VmError::NativeExecution {
                                    op: "uc_reg_read(ebx)",
                                    detail,
                                },
                            )?;
                            let ebp = unsafe { api.reg_read_raw(uc, UC_X86_REG_EBP) }.map_err(
                                |detail| VmError::NativeExecution {
                                    op: "uc_reg_read(ebp)",
                                    detail,
                                },
                            )?;
                            let esi = unsafe { api.reg_read_raw(uc, UC_X86_REG_ESI) }.map_err(
                                |detail| VmError::NativeExecution {
                                    op: "uc_reg_read(esi)",
                                    detail,
                                },
                            )?;
                            let edi = unsafe { api.reg_read_raw(uc, UC_X86_REG_EDI) }.map_err(
                                |detail| VmError::NativeExecution {
                                    op: "uc_reg_read(edi)",
                                    detail,
                                },
                            )?;
                            (return_address, args, esp, Some((ebx, ebp, esi, edi)))
                        } else {
                            let rsp = unsafe { api.reg_read_raw(uc, UC_X86_REG_RSP) }.map_err(
                                |detail| VmError::NativeExecution {
                                    op: "uc_reg_read(rsp)",
                                    detail,
                                },
                            )?;
                            let return_address = unsafe { api.mem_read_raw(uc, rsp, 8) }
                                .map_err(|detail| VmError::NativeExecution {
                                    op: "uc_mem_read(stack)",
                                    detail,
                                })
                                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))?;
                            let mut args = Vec::with_capacity(definition.argc);
                            for (regid, op) in [
                                (UC_X86_REG_RCX, "uc_reg_read(rcx)"),
                                (UC_X86_REG_RDX, "uc_reg_read(rdx)"),
                                (UC_X86_REG_R8, "uc_reg_read(r8)"),
                                (UC_X86_REG_R9, "uc_reg_read(r9)"),
                            ]
                            .into_iter()
                            .take(definition.argc.min(4))
                            {
                                args.push(
                                    unsafe { api.reg_read_raw(uc, regid) }.map_err(|detail| {
                                        VmError::NativeExecution { op, detail }
                                    })?,
                                );
                            }
                            if definition.argc > 4 {
                                let stack_args = unsafe {
                                    api.mem_read_raw(uc, rsp + 0x28, (definition.argc - 4) * 8)
                                }
                                .map_err(|detail| VmError::NativeExecution {
                                    op: "uc_mem_read(stack_args)",
                                    detail,
                                })?;
                                for chunk in stack_args.chunks_exact(8) {
                                    args.push(u64::from_le_bytes(chunk.try_into().unwrap()));
                                }
                            }
                            (return_address, args, rsp, None)
                        };
                    let retval = engine.dispatch_bound_stub_with_definition(
                        &definition,
                        address,
                        Some(return_address),
                        &args,
                    )?;
                    if let Some(restore) = engine.pending_context_restore.take() {
                        engine.defer_api_return = false;
                        engine.restore_unicorn_thread_registers(api, uc, &restore.registers)?;
                        if engine.arch.is_x86() {
                            engine.restore_unicorn_x86_segments_from_context(
                                api,
                                uc,
                                restore.context_address,
                            )?;
                        }
                    } else if !engine.defer_api_return {
                        if engine.arch.is_x86() {
                            unsafe { api.reg_write_raw(uc, UC_X86_REG_EAX, retval) }.map_err(
                                |detail| VmError::NativeExecution {
                                    op: "uc_reg_write(eax)",
                                    detail,
                                },
                            )?;
                            if definition.function == "VerSetConditionMask" {
                                unsafe { api.reg_write_raw(uc, UC_X86_REG_EDX, retval >> 32) }
                                    .map_err(|detail| VmError::NativeExecution {
                                        op: "uc_reg_write(edx)",
                                        detail,
                                    })?;
                            }
                            let next_esp = match definition.call_conv {
                                CallConv::Stdcall => stack_pointer + 4 + definition.argc as u64 * 4,
                                CallConv::Cdecl => stack_pointer + 4,
                                CallConv::Win64 => {
                                    return Err(VmError::NativeExecution {
                                        op: "dispatch",
                                        detail: format!(
                                            "win64 hook dispatch is not supported for {}!{}",
                                            definition.module, definition.function
                                        ),
                                    });
                                }
                            };
                            if let Some((saved_ebx, saved_ebp, saved_esi, saved_edi)) =
                                saved_x86_nonvolatile
                            {
                                unsafe { api.reg_write_raw(uc, UC_X86_REG_EBX, saved_ebx) }
                                    .map_err(|detail| VmError::NativeExecution {
                                        op: "uc_reg_write(ebx)",
                                        detail,
                                    })?;
                                unsafe { api.reg_write_raw(uc, UC_X86_REG_EBP, saved_ebp) }
                                    .map_err(|detail| VmError::NativeExecution {
                                        op: "uc_reg_write(ebp)",
                                        detail,
                                    })?;
                                unsafe { api.reg_write_raw(uc, UC_X86_REG_ESI, saved_esi) }
                                    .map_err(|detail| VmError::NativeExecution {
                                        op: "uc_reg_write(esi)",
                                        detail,
                                    })?;
                                unsafe { api.reg_write_raw(uc, UC_X86_REG_EDI, saved_edi) }
                                    .map_err(|detail| VmError::NativeExecution {
                                        op: "uc_reg_write(edi)",
                                        detail,
                                    })?;
                            }
                            unsafe { api.reg_write_raw(uc, UC_X86_REG_ESP, next_esp) }.map_err(
                                |detail| VmError::NativeExecution {
                                    op: "uc_reg_write(esp)",
                                    detail,
                                },
                            )?;
                            let next_eip = if engine.force_native_return {
                                engine.force_native_return = false;
                                engine.native_return_sentinel
                            } else {
                                return_address
                            };
                            unsafe { api.reg_write_raw(uc, UC_X86_REG_EIP, next_eip) }.map_err(
                                |detail| VmError::NativeExecution {
                                    op: "uc_reg_write(eip)",
                                    detail,
                                },
                            )?;
                        } else {
                            unsafe { api.reg_write_raw(uc, UC_X86_REG_RAX, retval) }.map_err(
                                |detail| VmError::NativeExecution {
                                    op: "uc_reg_write(rax)",
                                    detail,
                                },
                            )?;
                            unsafe { api.reg_write_raw(uc, UC_X86_REG_RSP, stack_pointer + 8) }
                                .map_err(|detail| VmError::NativeExecution {
                                    op: "uc_reg_write(rsp)",
                                    detail,
                                })?;
                            let next_rip = if engine.force_native_return {
                                engine.force_native_return = false;
                                engine.native_return_sentinel
                            } else {
                                return_address
                            };
                            unsafe { api.reg_write_raw(uc, UC_X86_REG_RIP, next_rip) }.map_err(
                                |detail| VmError::NativeExecution {
                                    op: "uc_reg_write(rip)",
                                    detail,
                                },
                            )?;
                        }
                    }
                    if engine.thread_yield_requested {
                        let _ = unsafe { api.emu_stop_raw(uc) };
                    }
                    Ok(())
                })();

            if let Err(error) = result {
                state.callback_error = Some(error);
                let _ = unsafe {
                    api.reg_write_raw(
                        uc,
                        if engine.arch.is_x86() {
                            UC_X86_REG_EIP
                        } else {
                            UC_X86_REG_RIP
                        },
                        engine.native_return_sentinel,
                    )
                };
                let _ = unsafe { api.emu_stop_raw(uc) };
            }
        } else {
            let bound_module = bound.module.to_string();
            let bound_function = bound.function.to_string();
            let _ = engine.log_unsupported_bound_stub(
                address,
                &bound_module,
                &bound_function,
                "missing hook definition",
            );
            let detail = format!(
                "missing runtime definition for bound stub 0x{address:X}: {}!{}",
                bound_module, bound_function
            );
            state.callback_error = Some(VmError::NativeExecution {
                op: "dispatch",
                detail,
            });
            let _ = unsafe {
                api.reg_write_raw(
                    uc,
                    if engine.arch.is_x86() {
                        UC_X86_REG_EIP
                    } else {
                        UC_X86_REG_RIP
                    },
                    engine.native_return_sentinel,
                )
            };
            let _ = unsafe { api.emu_stop_raw(uc) };
        }
    }
}

unsafe extern "C" fn unicorn_block_hook(
    uc: *mut UcEngine,
    address: u64,
    size: u32,
    _user_data: *mut c_void,
) {
    let state_ptr = ACTIVE_UNICORN_CONTEXT.with(|slot| slot.get());
    if state_ptr.is_null() {
        return;
    }
    let state = &mut *state_ptr;
    if state.callback_error.is_some() {
        return;
    }
    if state.last_native_block == Some((address, size)) {
        return;
    }
    state.last_native_block = Some((address, size));

    let engine = &mut *state.engine;
    let api = &*state.api;
    if engine.api_logger.native_trace_sampling_enabled() {
        match engine.capture_unicorn_thread_registers(api, uc) {
            Ok(registers) => {
                const NATIVE_BLOCK_WINDOW: usize = 32;
                if state.recent_blocks.len() == NATIVE_BLOCK_WINDOW {
                    state.recent_blocks.pop_front();
                }
                let stack_words = engine
                    .capture_unicorn_stack_words(api, uc, &registers)
                    .unwrap_or_default();
                state.recent_blocks.push_back(NativeBlockSnapshot {
                    pc: address,
                    size,
                    registers,
                    stack_words,
                });
            }
            Err(error) => {
                state.callback_error = Some(error);
                let _ = unsafe { api.emu_stop_raw(uc) };
                return;
            }
        }
    }
    let latest_snapshot = state.recent_blocks.back().cloned();
    if let Err(error) = engine.log_native_block(address, size, latest_snapshot.as_ref()) {
        state.callback_error = Some(error);
        let _ = unsafe { api.emu_stop_raw(uc) };
    }
}

unsafe extern "C" fn unicorn_mem_write_hook(
    uc: *mut UcEngine,
    _mem_type: i32,
    address: u64,
    size: i32,
    _value: i64,
    _user_data: *mut c_void,
) {
    let state_ptr = ACTIVE_UNICORN_CONTEXT.with(|slot| slot.get());
    if state_ptr.is_null() {
        return;
    }
    let state = &mut *state_ptr;
    if state.callback_error.is_some() || state.suppress_mem_write_hook || size <= 0 {
        return;
    }
    let size = size as usize;
    if let Some((previous_address, previous_size)) = state.pending_writes.last_mut() {
        let previous_end = previous_address.saturating_add(*previous_size as u64);
        if previous_end == address {
            *previous_size = previous_size.saturating_add(size);
            return;
        }
    }
    state.pending_writes.push((address, size));
    let _ = uc;
}

unsafe extern "C" fn unicorn_mem_prot_hook(
    uc: *mut UcEngine,
    mem_type: i32,
    address: u64,
    size: i32,
    _value: i64,
    _user_data: *mut c_void,
) -> bool {
    let state_ptr = ACTIVE_UNICORN_CONTEXT.with(|slot| slot.get());
    if state_ptr.is_null() {
        return false;
    }
    let state = &mut *state_ptr;
    if state.callback_error.is_some() || state.pending_fault.is_some() || size <= 0 {
        return false;
    }
    if let Err(error) = flush_unicorn_pending_writes(state, uc) {
        state.callback_error = Some(error);
        return false;
    }

    let engine = &mut *state.engine;
    let api = &*state.api;
    let cleared = engine.consume_guard_pages_on_access(
        engine.current_process_space_key(),
        address,
        size as usize,
    );
    let had_guard_pages = !cleared.is_empty();
    for &(base, size, protect) in &cleared {
        let perms = VirtualExecutionEngine::perms_from_page_protect(protect).unwrap_or(0);
        if let Err(detail) = unsafe { api.mem_protect_raw(uc, base, size, unicorn_prot(perms)) } {
            state.callback_error = Some(VmError::NativeExecution {
                op: "uc_mem_protect(guard)",
                detail,
            });
            return false;
        }
    }
    let registers = engine.capture_unicorn_thread_registers(api, uc).ok();
    let pc = registers
        .as_ref()
        .and_then(|snapshot| snapshot.get(if engine.arch.is_x86() { "eip" } else { "rip" }))
        .copied()
        .unwrap_or(0);
    let access = match mem_type {
        crate::runtime::unicorn::UC_MEM_FETCH_PROT => UnicornFaultAccess::Execute,
        crate::runtime::unicorn::UC_MEM_WRITE_PROT => UnicornFaultAccess::Write,
        _ => UnicornFaultAccess::Read,
    };
    if !had_guard_pages {
        if let Err(error) = engine.log_native_fault(
            "protected",
            access.as_str(),
            pc,
            address,
            size as usize,
            registers.as_ref(),
            None,
        ) {
            state.callback_error = Some(error);
            return false;
        }
        if let Err(error) = engine.log_native_fault_window(&state.recent_blocks) {
            state.callback_error = Some(error);
            return false;
        }
        state.pending_fault = Some(UnicornFault {
            access,
            address,
            size: size as usize,
            pc,
        });
        let _ = unsafe { api.emu_stop_raw(uc) };
        return false;
    }
    if let Err(error) = engine.log_native_fault(
        "guard",
        access.as_str(),
        pc,
        address,
        size as usize,
        registers.as_ref(),
        Some("guard page"),
    ) {
        state.callback_error = Some(error);
        return false;
    }
    if let Err(error) = engine.log_native_fault_window(&state.recent_blocks) {
        state.callback_error = Some(error);
        return false;
    }
    state.callback_error = Some(VmError::NativeExecution {
        op: "guard page",
        detail: format!("guard page {} at 0x{address:X}", access.as_str()),
    });
    false
}

unsafe extern "C" fn unicorn_mem_unmapped_hook(
    uc: *mut UcEngine,
    mem_type: i32,
    address: u64,
    size: i32,
    _value: i64,
    _user_data: *mut c_void,
) -> bool {
    let state_ptr = ACTIVE_UNICORN_CONTEXT.with(|slot| slot.get());
    if state_ptr.is_null() {
        return false;
    }
    let state = &mut *state_ptr;
    if state.callback_error.is_some() || state.pending_fault.is_some() || size <= 0 {
        return false;
    }
    if let Err(error) = flush_unicorn_pending_writes(state, uc) {
        state.callback_error = Some(error);
        return false;
    }

    let engine = &mut *state.engine;
    let api = &*state.api;
    let pc_reg = if engine.arch.is_x86() {
        UC_X86_REG_EIP
    } else {
        UC_X86_REG_RIP
    };
    let pc = match unsafe { api.reg_read_raw(uc, pc_reg) } {
        Ok(value) => value,
        Err(detail) => {
            state.callback_error = Some(VmError::NativeExecution {
                op: "uc_reg_read(pc)",
                detail,
            });
            return false;
        }
    };
    let access = match mem_type {
        crate::runtime::unicorn::UC_MEM_FETCH_UNMAPPED => UnicornFaultAccess::Execute,
        crate::runtime::unicorn::UC_MEM_WRITE_UNMAPPED => UnicornFaultAccess::Write,
        _ => UnicornFaultAccess::Read,
    };
    let registers = engine.capture_unicorn_thread_registers(api, uc).ok();
    if let Err(error) = engine.log_native_fault(
        "unmapped",
        access.as_str(),
        pc,
        address,
        size as usize,
        registers.as_ref(),
        None,
    ) {
        state.callback_error = Some(error);
        return false;
    }
    if let Err(error) = engine.log_native_fault_window(&state.recent_blocks) {
        state.callback_error = Some(error);
        return false;
    }
    state.pending_fault = Some(UnicornFault {
        access,
        address,
        size: size as usize,
        pc,
    });
    let _ = unsafe { api.emu_stop_raw(uc) };
    false
}

/// Renders the Python-compatible `run` summary fields emitted by the Rust CLI.
pub fn render_run_summary(result: &RunResult) -> String {
    format!(
        "entrypoint=0x{:X}\ninstructions={}\nstopped={}\nexit_code={}\nstop_reason={}\n",
        result.entrypoint,
        result.instructions,
        result.stopped,
        result
            .exit_code
            .map(|value| value.to_string())
            .unwrap_or_else(|| "None".to_string()),
        result.stop_reason.as_str(),
    )
}
