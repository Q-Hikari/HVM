//! Engine state type definitions extracted from engine.rs.
//!
//! Contains all state structs, enums, and their impl blocks used by
//! VirtualExecutionEngine and its subsystems.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use super::NativeTraceState;
use crate::arch::ArchSpec;
use crate::config::EngineConfig;
use crate::environment_profile::EnvironmentProfile;
use crate::hooks::registry::HookRegistry;
use crate::managers::crypto_manager::CryptoManager;
use crate::managers::device_manager::DeviceManager;
use crate::managers::file_mapping_manager::FileMappingManager;
use crate::managers::heap_manager::HeapManager;
use crate::managers::module_manager::ModuleManager;
use crate::managers::network_manager::NetworkManager;
use crate::managers::process_manager::ProcessManager;
use crate::managers::registry_manager::RegistryManager;
use crate::managers::service_manager::ServiceManager;
use crate::managers::time_manager::TimeManager;
use crate::managers::tls_manager::TlsManager;
use crate::memory::manager::MemoryManager;
use crate::models::{ModuleRecord, RunStopReason};
use crate::runtime::api_logger::ApiExecutionContext;
use crate::runtime::api_logger::ApiLogger;
use crate::runtime::engine::shared::RemoteShellcodeThread;
use crate::runtime::engine::ui::User32State;
use crate::runtime::profiler::RuntimeProfiler;
use crate::runtime::scheduler::ThreadScheduler;
use crate::runtime::thread_context::RegisterFile;
use crate::runtime::unicorn::{UcEngine, UnicornApi};
use crate::runtime::windows_env::WindowsProcessEnvironment;
use rand::rngs::StdRng;

#[derive(Debug)]
pub struct FileHandleState {
    pub(super) file: std::fs::File,
    pub(super) path: String,
    pub(super) writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FindFileEntry {
    pub(super) file_name: String,
    pub(super) attributes: u32,
    pub(super) size: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FindHandleState {
    pub(super) entries: Vec<FindFileEntry>,
    pub(super) cursor: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeFindHandleState {
    pub(super) entries: Vec<String>,
    pub(super) cursor: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceHandleState {
    pub(super) path: String,
    pub(super) physical_drive_index: Option<u32>,
    pub(super) position: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoCompletionPacket {
    pub(super) bytes_transferred: u32,
    pub(super) completion_key: u64,
    pub(super) overlapped: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetupDeviceInfoSetState {
    pub(super) devices: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedVolume {
    pub(super) host_path: std::path::PathBuf,
    pub(super) guest_path: String,
    pub(super) guest_components: Vec<String>,
    pub(super) recursive: bool,
    pub(super) host_is_dir: bool,
    pub(super) priority: u8,
}

#[derive(Debug, Default, Clone)]
pub struct MsvcrtOnExitTable {
    pub(super) storage: Option<u64>,
    pub(super) capacity: usize,
    pub(super) functions: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticProcessIdentity {
    pub(super) pid: u32,
    pub(super) parent_pid: u32,
    pub(super) image_path: String,
    pub(super) command_line: String,
    pub(super) current_directory: String,
}

impl SyntheticProcessIdentity {
    pub(super) fn image_name(&self) -> String {
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

    pub(super) fn display_path(&self) -> &str {
        if self.image_path.is_empty() {
            &self.command_line
        } else {
            &self.image_path
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ToolhelpProcessEntry {
    pub(super) pid: u32,
    pub(super) parent_pid: u32,
    pub(super) thread_count: u32,
    pub(super) image_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolhelpProcessSnapshot {
    pub(super) entries: Vec<ToolhelpProcessEntry>,
    pub(super) next_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VirtualAllocationSegment {
    pub(super) base: u64,
    pub(super) size: u64,
    pub(super) state: u32,
    pub(super) protect: u32,
}

impl VirtualAllocationSegment {
    pub(super) fn end(&self) -> u64 {
        self.base + self.size
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualAllocationRecord {
    pub(super) allocation_base: u64,
    pub(super) allocation_size: u64,
    pub(super) allocation_protect: u32,
    pub(super) allocation_type: u32,
    pub(super) region_type: u32,
    pub(super) segments: Vec<VirtualAllocationSegment>,
}

impl VirtualAllocationRecord {
    pub(super) fn end(&self) -> u64 {
        self.allocation_base + self.allocation_size
    }

    pub(super) fn contains(&self, address: u64) -> bool {
        self.allocation_base <= address && address < self.end()
    }

    pub(super) fn segment_for_address(&self, address: u64) -> Option<&VirtualAllocationSegment> {
        let index = self
            .segments
            .partition_point(|segment| segment.base <= address);
        index
            .checked_sub(1)
            .and_then(|i| self.segments.get(i))
            .filter(|segment| address < segment.end())
    }

    pub(super) fn replace_range(
        &mut self,
        start: u64,
        size: u64,
        state: u32,
        protect: u32,
    ) -> bool {
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

    pub(super) fn merge_segments(
        segments: Vec<VirtualAllocationSegment>,
    ) -> Vec<VirtualAllocationSegment> {
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
pub struct SyntheticProcessSpace {
    pub(super) memory: MemoryManager,
    pub(super) process_env: WindowsProcessEnvironment,
    pub(super) modules: Vec<ModuleRecord>,
    pub(super) virtual_allocations: BTreeMap<u64, VirtualAllocationRecord>,
}

impl SyntheticProcessSpace {
    pub(super) fn new(arch: &'static ArchSpec) -> Self {
        Self {
            memory: MemoryManager::for_arch(arch),
            process_env: WindowsProcessEnvironment::for_tests(arch),
            modules: Vec::new(),
            virtual_allocations: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryInvocation {
    NativeEntrypoint,
    Export,
}

#[derive(Debug, Clone)]
pub struct PendingContextRestore {
    pub(super) context_address: u64,
    pub(super) registers: RegisterFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveX64SyntheticCall {
    pub(super) caller_rsp: u64,
}

#[derive(Debug, Clone)]
pub struct PendingX86SehUnwind {
    pub(super) context_address: u64,
    pub(super) registers: RegisterFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingMsvcrtInitterm {
    pub(super) entry_rsp: u64,
    pub(super) resume_rsp: u64,
    pub(super) return_address: u64,
    pub(super) next_cursor: u64,
    pub(super) last: u64,
    pub(super) stop_on_nonzero: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingUser32TimerCallback {
    pub(super) entry_rsp: u64,
    pub(super) resume_rsp: u64,
    pub(super) return_address: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingUser32SendMessageCallback {
    pub(super) entry_rsp: u64,
    pub(super) resume_rsp: u64,
    pub(super) return_address: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveHookContext {
    pub(super) stub_address: u64,
    pub(super) return_address: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredGuestExceptionInHook {
    pub(super) stub_address: u64,
    pub(super) return_address: Option<u64>,
    pub(super) fault_address: u64,
    pub(super) fault_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookReturnOverride {
    pub(super) raw_retval: u64,
    pub(super) flags_mask: u64,
    pub(super) flags_value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingUser32EnumWindowsCallback {
    pub(super) entry_rsp: u64,
    pub(super) resume_rsp: u64,
    pub(super) return_address: u64,
    pub(super) callback: u64,
    pub(super) l_param: u64,
    pub(super) next_index: usize,
    pub(super) window_handles: Vec<u32>,
    pub(super) callee_saved: CalleeSavedRegisters,
}

/// Callee-saved registers that must be preserved across callback dispatch.
///
/// x86 cdecl preserves: EBX, ESI, EDI, EBP.
/// x64 Win64 preserves: RBX, RSI, RDI, RBP, R12–R15.
///
/// Unused fields are zero for the non-active architecture.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct CalleeSavedRegisters {
    pub(super) rbx: u64,
    pub(super) rsi: u64,
    pub(super) rdi: u64,
    pub(super) rbp: u64,
    pub(super) r12: u64,
    pub(super) r13: u64,
    pub(super) r14: u64,
    pub(super) r15: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLdrEnumCallback {
    pub(super) entry_rsp: u64,
    pub(super) resume_rsp: u64,
    pub(super) return_address: u64,
    pub(super) callback: u64,
    pub(super) context: u64,
    pub(super) next_index: usize,
    /// Address of the BOOLEAN Stop variable allocated on the stack or heap.
    pub(super) stop_var: u64,
    /// Base addresses of the loader entry (LDR_DATA_TABLE_ENTRY*) for each module.
    pub(super) module_entries: Vec<u64>,
    /// Callee-saved registers captured at enumeration start, restored on completion.
    pub(super) callee_saved: CalleeSavedRegisters,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEnvironmentVariable {
    pub(super) name: String,
    pub(super) value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MutexState {
    pub(super) owner_tid: Option<u32>,
    pub(super) recursion_count: u32,
    pub(super) abandoned: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SemaphoreState {
    pub(super) current_count: u32,
    pub(super) maximum_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DynamicCodeWriteObservation {
    pub(super) source: String,
    pub(super) remote: bool,
    pub(super) source_buffer: u64,
    pub(super) target_address: u64,
    pub(super) size: u64,
    pub(super) dump_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DynamicCodeProtectObservation {
    pub(super) source: String,
    pub(super) remote: bool,
    pub(super) address: u64,
    pub(super) size: u64,
    pub(super) old_protect: u32,
    pub(super) new_protect: u32,
    pub(super) became_executable: bool,
    pub(super) dump_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DynamicCodeThreadObservation {
    pub(super) trigger: String,
    pub(super) tid: u32,
    pub(super) handle: u32,
    pub(super) start_address: u64,
    pub(super) parameter: u64,
    pub(super) state: String,
    pub(super) dump_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicCodeRegionActivity {
    pub(super) process_key: u64,
    pub(super) allocation_base: u64,
    pub(super) region_base: u64,
    pub(super) region_size: u64,
    pub(super) region_type: u32,
    pub(super) last_stage: String,
    pub(super) write: Option<DynamicCodeWriteObservation>,
    pub(super) protect: Option<DynamicCodeProtectObservation>,
    pub(super) thread: Option<DynamicCodeThreadObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageHashBaseline {
    pub(super) capture_size: u64,
    pub(super) hash: u64,
}

// ---------------------------------------------------------------------------
// Subsystem structs (P2-5 refactoring — field grouping, no behavior change)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(super) struct EngineCore {
    pub arch: &'static ArchSpec,
    pub config: EngineConfig,
    pub environment_profile: EnvironmentProfile,
    pub hooks: HookRegistry,
    pub modules: ModuleManager,
    pub scheduler: ThreadScheduler,
    pub process_env: WindowsProcessEnvironment,
    pub processes: ProcessManager,
    pub registry: RegistryManager,
    pub api_logger: ApiLogger,
    pub runtime_profiler: RuntimeProfiler,
    pub api_call_counts: BTreeMap<String, u64>,

    pub loaded: bool,
    pub instruction_count: u64,
    pub emu_floor_instructions: u64,
    pub instructions_since_time_advance: u64,
    pub exit_code: Option<u32>,
    pub stop_reason: Option<RunStopReason>,
    pub process_exit_requested: bool,
    pub startup_sequence_completed: bool,
    pub native_return_sentinel: u64,

    pub main_module: Option<ModuleRecord>,
    pub entry_module: Option<ModuleRecord>,
    pub parent_process: Option<SyntheticProcessIdentity>,
    pub entry_address: Option<u64>,
    pub entry_arguments: Vec<u64>,
    pub entry_invocation: EntryInvocation,
    pub entry_module_requires_attach: bool,
    pub command_line: String,
    pub dll_directory: Option<String>,
    pub current_directory: std::path::PathBuf,
    pub current_directory_host: std::path::PathBuf,
    pub environment_variables: BTreeMap<String, RuntimeEnvironmentVariable>,
    pub main_thread_tid: Option<u32>,
    pub last_error: u32,
    pub observation_checkpoints: Vec<u64>,
    pub next_checkpoint_index: usize,
    pub debug_pc_probes: BTreeSet<u64>,
}

#[derive(Debug, Default)]
pub(super) struct SyncState {
    pub mutex_handles: BTreeSet<u32>,
    pub mutex_handle_targets: HashMap<u32, u32>,
    pub mutex_states: HashMap<u32, MutexState>,
    pub named_mutexes: HashMap<String, u32>,
    pub semaphore_handles: BTreeSet<u32>,
    pub semaphore_handle_targets: HashMap<u32, u32>,
    pub semaphore_states: HashMap<u32, SemaphoreState>,
    pub named_semaphores: HashMap<String, u32>,
}

#[derive(Debug)]
pub(super) struct HandleState {
    pub next_file_handle: u32,
    pub next_object_handle: u32,
    pub file_handles: HashMap<u32, FileHandleState>,
    pub find_handles: HashMap<u32, FindHandleState>,
    pub volume_find_handles: HashMap<u32, VolumeFindHandleState>,
    pub device_handles: HashMap<u32, DeviceHandleState>,
    pub io_completion_ports: HashMap<u32, VecDeque<IoCompletionPacket>>,
    pub setup_device_sets: HashMap<u32, SetupDeviceInfoSetState>,
    pub token_handles: BTreeSet<u32>,
    pub etw_trace_handles: BTreeSet<u32>,
}

impl Default for HandleState {
    fn default() -> Self {
        Self {
            next_file_handle: 0x1000,
            next_object_handle: 0x8004,
            file_handles: HashMap::new(),
            find_handles: HashMap::new(),
            volume_find_handles: HashMap::new(),
            device_handles: HashMap::new(),
            io_completion_ports: HashMap::new(),
            setup_device_sets: HashMap::new(),
            token_handles: BTreeSet::new(),
            etw_trace_handles: BTreeSet::new(),
        }
    }
}

#[derive(Debug)]
pub(super) struct ProcessMemoryState {
    pub virtual_allocations: BTreeMap<u64, VirtualAllocationRecord>,
    pub process_handles: HashMap<u32, u32>,
    pub process_spaces: HashMap<u64, SyntheticProcessSpace>,
    /// Synthetic process identities created on-the-fly for OpenProcess targets
    /// that are not in the environment profile's process list.
    pub synthetic_process_identities: Vec<SyntheticProcessIdentity>,
    pub process_snapshots: HashMap<u32, ToolhelpProcessSnapshot>,
    pub file_mappings: FileMappingManager,
    pub heaps: HeapManager,
}

// ProcessMemoryState: no Default — heaps & file_mappings need live MemoryManager

#[derive(Debug, Default)]
pub(super) struct SyncObjectsState {
    pub dynamic_library_refs: HashMap<u64, u32>,
    pub startup_pinned_modules: BTreeSet<u64>,
    pub attached_process_modules: BTreeSet<u64>,
    pub pending_thread_attach: BTreeSet<u32>,
    pub started_threads: BTreeSet<u32>,
    pub wts_server_handles: BTreeSet<u32>,
    pub global_atoms: HashMap<u16, String>,
    pub next_atom: u16,
    pub mounted_volumes: Vec<MountedVolume>,
}

/// Auto-assigns unique synthetic IPs to hostnames for DNS resolution.
#[derive(Debug, Default)]
pub(super) struct DnsMap {
    next_ip: u32,
    host_to_ip: BTreeMap<String, String>,
    ip_to_host: BTreeMap<String, String>,
}

impl DnsMap {
    pub(super) fn new() -> Self {
        // Start from 100.64.0.1 (Carrier-Grade NAT range, unused in typical emulation)
        Self {
            next_ip: 0x6440_0001,
            ..Default::default()
        }
    }

    pub(super) fn resolve(&mut self, host: &str) -> String {
        if let Some(ip) = self.host_to_ip.get(host) {
            return ip.clone();
        }
        let a = (self.next_ip >> 24) as u8;
        let b = (self.next_ip >> 16) as u8;
        let c = (self.next_ip >> 8) as u8;
        let d = self.next_ip as u8;
        let ip = format!("{}.{}.{}.{}", a, b, c, d);
        self.next_ip = self.next_ip.wrapping_add(1);
        self.host_to_ip.insert(host.to_string(), ip.clone());
        self.ip_to_host.insert(ip.clone(), host.to_string());
        ip
    }

    pub(super) fn reverse(&self, ip: &str) -> Option<&String> {
        self.ip_to_host.get(ip)
    }
}

#[derive(Debug)]
pub(super) struct NetworkState {
    pub network: NetworkManager,
    pub crypto: CryptoManager,
    pub http_response_rule_hits: BTreeMap<usize, u64>,
    pub dns: DnsMap,
    pub inet_ntoa_buffer: Option<u64>,
    pub consecutive_empty_selects: u64,
    pub socket_event_masks: BTreeMap<u32, i32>,
    pub socket_event_handles: BTreeMap<u32, u32>,
}

// NetworkState: no Default — NetworkManager/CryptoManager need constructors

#[derive(Debug)]
pub(super) struct UiState {
    pub user32_state: User32State,
    pub shell_imalloc: Option<u64>,
    pub pending_user32_timer_callbacks: Vec<PendingUser32TimerCallback>,
    pub pending_user32_sendmessage_callbacks: Vec<PendingUser32SendMessageCallback>,
    pub pending_user32_enumwindows_callbacks: Vec<PendingUser32EnumWindowsCallback>,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            user32_state: User32State::default(),
            shell_imalloc: None,
            pending_user32_timer_callbacks: Vec::new(),
            pending_user32_sendmessage_callbacks: Vec::new(),
            pending_user32_enumwindows_callbacks: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub(super) struct CrtState {
    pub msvcrt_globals_base: Option<u64>,
    pub msvcrt_onexit_tables: HashMap<u64, MsvcrtOnExitTable>,
    pub msvcrt_rand_seed: u32,
    pub pending_msvcrt_initterm: Vec<PendingMsvcrtInitterm>,
}

impl Default for CrtState {
    fn default() -> Self {
        Self {
            msvcrt_globals_base: None,
            msvcrt_onexit_tables: HashMap::new(),
            msvcrt_rand_seed: 1,
            pending_msvcrt_initterm: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VectoredExceptionHandler {
    pub handle: u32,
    pub handler: u64,
}

#[derive(Debug)]
pub(super) struct ExceptionState {
    pub top_level_exception_filter: u64,
    pub dispatching_top_level_exception_filter: bool,
    pub vectored_exception_handlers: Vec<VectoredExceptionHandler>,
    pub pending_x64_top_level_filter_seed: Option<RegisterFile>,
    pub x64_top_level_exception_filter_thunks: BTreeMap<u64, u64>,
    pub pending_context_restore: Option<PendingContextRestore>,
    pub pending_x86_seh_unwind: Option<PendingX86SehUnwind>,
}

impl Default for ExceptionState {
    fn default() -> Self {
        Self {
            top_level_exception_filter: 0,
            dispatching_top_level_exception_filter: false,
            vectored_exception_handlers: Vec::new(),
            pending_x64_top_level_filter_seed: None,
            x64_top_level_exception_filter_thunks: BTreeMap::new(),
            pending_context_restore: None,
            pending_x86_seh_unwind: None,
        }
    }
}

#[derive(Debug)]
pub(super) struct NativeTraceSubsystem {
    pub native_trace: NativeTraceState,
    pub memory_dump_sequence: u64,
    pub dynamic_code_activities: HashMap<(u64, u64), DynamicCodeRegionActivity>,
    pub image_hash_baselines: HashMap<(u64, u64), ImageHashBaseline>,
    pub remote_shellcode_threads: HashMap<u32, RemoteShellcodeThread>,
    pub active_x64_synthetic_call: Option<ActiveX64SyntheticCall>,
    #[allow(dead_code)]
    pub diag_block_count: u64,
}

impl Default for NativeTraceSubsystem {
    fn default() -> Self {
        Self {
            native_trace: NativeTraceState::default(),
            memory_dump_sequence: 0,
            dynamic_code_activities: HashMap::new(),
            image_hash_baselines: HashMap::new(),
            remote_shellcode_threads: HashMap::new(),
            active_x64_synthetic_call: None,
            diag_block_count: 0,
        }
    }
}

#[derive(Debug)]
pub(super) struct UnicornState {
    pub unicorn: Option<Box<UnicornApi>>,
    pub unicorn_handle: Option<*mut UcEngine>,
    pub unicorn_intr_hook_installed: bool,
    pub unicorn_block_hook_installed: bool,
    pub unicorn_code_hook_installed: bool,
    pub unicorn_mem_write_hook_installed: bool,
    pub unicorn_mem_read_hook_installed: bool,
    pub unicorn_mem_prot_hook_installed: bool,
    pub unicorn_mem_unmapped_hook_installed: bool,
}

impl Default for UnicornState {
    fn default() -> Self {
        Self {
            unicorn: None,
            unicorn_handle: None,
            unicorn_intr_hook_installed: false,
            unicorn_block_hook_installed: false,
            unicorn_code_hook_installed: false,
            unicorn_mem_write_hook_installed: false,
            unicorn_mem_read_hook_installed: false,
            unicorn_mem_prot_hook_installed: false,
            unicorn_mem_unmapped_hook_installed: false,
        }
    }
}

// Safety: unicorn_handle is a raw pointer used only as an opaque handle
// to the Unicorn engine, never dereferenced outside of the Unicorn C API.
unsafe impl Send for UnicornState {}
unsafe impl Sync for UnicornState {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ApiFlowControl {
    Continue,
    ResumeAtUpdatedPc,
    YieldThread { defer_api_return: bool },
}

impl ApiFlowControl {
    pub(super) fn defers_api_return(self) -> bool {
        matches!(
            self,
            Self::ResumeAtUpdatedPc
                | Self::YieldThread {
                    defer_api_return: true,
                }
        )
    }

    pub(super) fn yields_thread(self) -> bool {
        matches!(self, Self::YieldThread { .. })
    }

    pub(super) fn resumes_at_updated_pc(self) -> bool {
        matches!(self, Self::ResumeAtUpdatedPc)
    }
}

#[derive(Debug)]
pub(super) struct DispatchState {
    pub api_flow_control: ApiFlowControl,
    pub preserve_blocked_api_frame: bool,
    pub force_native_return: bool,
    pub api_log_context_override: Option<ApiExecutionContext>,
    pub active_hook_context: Option<ActiveHookContext>,
    pub recovered_guest_exception_in_hook: Option<RecoveredGuestExceptionInHook>,
    pub pending_hook_return_override: Option<HookReturnOverride>,
    pub guid_rng: StdRng,
    pub tls: TlsManager,
    pub time: TimeManager,
    pub devices: DeviceManager,
    pub services: ServiceManager,
    /// API log suppression: consecutive identical (pc, target) calls
    pub suppress_last_api_pc: Option<u64>,
    pub suppress_last_api_target: Option<String>,
    pub suppress_api_count: u64,
    pub pending_ldr_enum_callbacks: Vec<PendingLdrEnumCallback>,
    pub com_message_filter: u64,
    pub completed_init_once: HashSet<u64>,
}

impl DispatchState {
    pub(super) fn reset_api_flow_control(&mut self) {
        self.api_flow_control = ApiFlowControl::Continue;
    }

    pub(super) fn begin_hook_dispatch(&mut self, stub_address: u64, return_address: Option<u64>) {
        self.active_hook_context = Some(ActiveHookContext {
            stub_address,
            return_address,
        });
        self.recovered_guest_exception_in_hook = None;
        self.pending_hook_return_override = None;
    }

    pub(super) fn end_hook_dispatch(&mut self) {
        self.active_hook_context = None;
    }

    pub(super) fn record_recovered_guest_exception_in_hook(
        &mut self,
        fault_address: u64,
        fault_size: usize,
    ) {
        let Some(active_hook) = self.active_hook_context else {
            return;
        };
        if self.recovered_guest_exception_in_hook.is_none() {
            self.recovered_guest_exception_in_hook = Some(RecoveredGuestExceptionInHook {
                stub_address: active_hook.stub_address,
                return_address: active_hook.return_address,
                fault_address,
                fault_size,
            });
        }
    }

    pub(super) fn take_recovered_guest_exception_in_hook(
        &mut self,
    ) -> Option<RecoveredGuestExceptionInHook> {
        self.recovered_guest_exception_in_hook.take()
    }

    pub(super) fn guest_exception_recovered_in_active_hook(&self) -> bool {
        self.recovered_guest_exception_in_hook.is_some()
    }

    pub(super) fn set_hook_return_override(
        &mut self,
        raw_retval: u64,
        flags_mask: u64,
        flags_value: u64,
    ) {
        self.pending_hook_return_override = Some(HookReturnOverride {
            raw_retval,
            flags_mask,
            flags_value,
        });
    }

    pub(super) fn hook_return_override(&self) -> Option<HookReturnOverride> {
        self.pending_hook_return_override
    }

    pub(super) fn take_hook_return_override(&mut self) -> Option<HookReturnOverride> {
        self.pending_hook_return_override.take()
    }

    pub(super) fn request_resume_at_updated_pc(&mut self) {
        self.api_flow_control = ApiFlowControl::ResumeAtUpdatedPc;
    }

    pub(super) fn request_thread_yield(&mut self, preserve_api_frame: bool) {
        self.api_flow_control = ApiFlowControl::YieldThread {
            defer_api_return: preserve_api_frame,
        };
    }

    pub(super) fn api_return_deferred(&self) -> bool {
        self.api_flow_control.defers_api_return()
    }

    pub(super) fn thread_yield_requested(&self) -> bool {
        self.api_flow_control.yields_thread()
    }

    pub(super) fn should_restart_from_updated_pc(&self) -> bool {
        self.api_flow_control.resumes_at_updated_pc()
    }
}
