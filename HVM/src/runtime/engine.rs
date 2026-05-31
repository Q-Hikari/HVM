use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
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
use smallvec::SmallVec;

use crate::arch::{arch_spec, ArchSpec};
use crate::config::{EngineConfig, EntryArgument, HttpResponseHeader, VolumeMount};
use crate::environment_profile::EnvironmentProfile;
use crate::error::{ConfigError, VmError};
use crate::hooks::families::core::ntdll::{
    STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_DLL_NOT_FOUND,
    STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_FILE_FOR_SECTION, STATUS_INVALID_HANDLE,
    STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_EXISTS, STATUS_PROCEDURE_NOT_FOUND, STATUS_SUCCESS,
};
use crate::hooks::families::shell_services::shell32::{
    SEE_MASK_NOCLOSEPROCESS, SHELL_EXECUTE_SUCCESS,
};
use crate::hooks::register_all_family_hooks;
use crate::hooks::registry::HookRegistry;
use crate::hooks::signature::HookSignature;
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
use crate::memory::manager::{PAGE_SIZE, PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::models::{ModuleRecord, RunResult, RunStopReason};
use crate::pe::imports::collect_import_bindings;
use crate::runtime::api_logger::{
    AddressRef, ApiExecutionContext, ApiLogArg, ApiLogger, ApiStackWord,
};
use crate::runtime::gbk_compat::gbk_pair_is_valid;
use crate::runtime::profiler::RuntimeProfiler;
use crate::runtime::scheduler::{ThreadScheduler, WAIT_IO_COMPLETION};
use crate::runtime::thread_context::{
    deserialize_register_context, register_file_to_map, serialize_register_context, RegisterFile,
};
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

mod abi;
mod constants;
mod core_helpers;
mod entry_helpers;
mod hook_context;
mod hook_value;
pub(super) use hook_context::HookContext;
pub(super) use hook_value::HookValue;
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
mod lifecycle_helpers;
mod logging_helpers;
mod memory_dump_helpers;
mod native_call_helpers;
mod native_unicorn_call_helpers;
#[path = "engine/hooks/network/mod.rs"]
mod network;
mod protected_fetch;
#[path = "engine/hooks/security/mod.rs"]
mod security;
#[path = "engine/shared/mod.rs"]
mod shared;
#[path = "engine/hooks/shell_services/mod.rs"]
mod shell_services;
#[path = "engine/hooks/ui/mod.rs"]
mod ui;
mod unicorn_helpers;
mod utilities;
mod x86_interpreter_helpers;

use protected_fetch::ProtectedFetchDecision;
use ui::User32State;
use utilities::{
    compare_ci, detect_runtime_architecture, is_std_handle, non_empty, seek_file, unicorn_prot,
    ArgAccess,
};
use x86_interpreter_helpers::X86State;

use constants::*;

mod state;
use state::*;

// DispatchState: no Default — guid_rng needs seed, services/devices need constructors

/// Owns the virtual execution engine and its subsystems.
#[derive(Debug)]
pub struct VirtualExecutionEngine {
    core: EngineCore,
    sync: SyncState,
    handles: HandleState,
    process_memory: ProcessMemoryState,
    objects: SyncObjectsState,
    network_state: NetworkState,
    ui: UiState,
    crt: CrtState,
    exception: ExceptionState,
    trace: NativeTraceSubsystem,
    unicorn_state: UnicornState,
    dispatch: DispatchState,
    behavior: crate::sandbox_result::BehaviorCollector,
}

impl VirtualExecutionEngine {
    fn debug_load_stage(&self, stage: &str) {
        if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_none() {
            return;
        }
        eprintln!(
            "[LOAD_STAGE] {stage} arch={} loaded={} modules={} current_tid={} main_tid={} teb=0x{:X} dirty_env={}",
            self.core.arch.name,
            self.core.loaded,
            self.core.modules.loaded_modules().len(),
            self.core.scheduler.current_tid().unwrap_or(0),
            self.core.main_thread_tid.unwrap_or(0),
            self.core.process_env.current_teb(),
            self.core.process_env.is_dirty(),
        );
    }

    /// Builds a new engine from the given configuration.
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
        if let Some(stack_reserve_size) = config.stack_reserve_size {
            if stack_reserve_size >= arch.stack_base {
                return Err(ConfigError::InvalidField {
                    field: "stack_reserve_size",
                    detail: format!(
                        "0x{stack_reserve_size:X} must be smaller than stack_base 0x{:X}",
                        arch.stack_base
                    ),
                }
                .into());
            }
            modules.memory_mut().set_stack_size(stack_reserve_size);
        }
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

        let api_logger = ApiLogger::new(&config)?;
        let runtime_profiler = RuntimeProfiler::from_env(&config);
        let observation_checkpoints = config.observation_checkpoints.clone();
        let tick_ms_base = environment_profile.time.tick_ms_base;
        let debug_pc_probes = parse_debug_pc_probes_from_env();

        Ok(Self {
            core: EngineCore {
                arch,
                config,
                environment_profile,
                hooks,
                modules,
                scheduler: ThreadScheduler::for_tests(),
                process_env: WindowsProcessEnvironment::for_tests(arch),
                processes: ProcessManager::for_tests(),
                registry,
                api_logger,
                runtime_profiler,
                api_call_counts: BTreeMap::new(),
                loaded: false,
                instruction_count: 0,
                emu_floor_instructions: 0,
                instructions_since_time_advance: 0,
                exit_code: None,
                stop_reason: None,
                process_exit_requested: false,
                startup_sequence_completed: false,
                native_return_sentinel,
                main_module: None,
                entry_module: None,
                parent_process: None,
                entry_address: None,
                entry_arguments: Vec::new(),
                entry_invocation: EntryInvocation::NativeEntrypoint,
                entry_module_requires_attach: false,
                command_line: String::new(),
                dll_directory: None,
                current_directory: std::path::PathBuf::new(),
                current_directory_host: std::path::PathBuf::new(),
                environment_variables: BTreeMap::new(),
                main_thread_tid: None,
                last_error: 0,
                observation_checkpoints,
                next_checkpoint_index: 0,
                debug_pc_probes,
            },
            sync: SyncState::default(),
            handles: HandleState::default(),
            process_memory: ProcessMemoryState {
                virtual_allocations: BTreeMap::new(),
                process_handles: HashMap::new(),
                process_spaces: HashMap::new(),
                synthetic_process_identities: Vec::new(),
                process_snapshots: HashMap::new(),
                file_mappings: FileMappingManager::new(),
                heaps,
            },
            objects: SyncObjectsState {
                mounted_volumes,
                ..SyncObjectsState::default()
            },
            network_state: NetworkState {
                network: NetworkManager::new(HandleTable::new(0xC000)),
                crypto: CryptoManager::new(HandleTable::new(0xD000)),
                http_response_rule_hits: BTreeMap::new(),
                dns: DnsMap::new(),
                inet_ntoa_buffer: None,
                consecutive_empty_selects: 0,
                socket_event_masks: BTreeMap::new(),
                socket_event_handles: BTreeMap::new(),
            },
            ui: UiState {
                user32_state,
                ..UiState::default()
            },
            crt: CrtState::default(),
            exception: ExceptionState::default(),
            trace: NativeTraceSubsystem::default(),
            unicorn_state: UnicornState {
                unicorn: UnicornApi::load_default().ok().map(Box::new),
                ..UnicornState::default()
            },
            dispatch: DispatchState {
                api_flow_control: ApiFlowControl::Continue,
                preserve_blocked_api_frame: false,
                force_native_return: false,
                api_log_context_override: None,
                active_hook_context: None,
                recovered_guest_exception_in_hook: None,
                pending_hook_return_override: None,
                guid_rng: StdRng::seed_from_u64(GUID_RNG_SEED),
                tls: TlsManager::new(),
                time: TimeManager::with_tick_ms_base(tick_ms_base),
                devices: DeviceManager::new(),
                services: ServiceManager::new(HandleTable::new(0xE000), service_inventory),
                suppress_last_api_pc: None,
                suppress_last_api_target: None,
                suppress_api_count: 0,
                pending_ldr_enum_callbacks: Vec::new(),
                com_message_filter: 0,
                completed_init_once: HashSet::new(),
            },
            behavior: crate::sandbox_result::BehaviorCollector::default(),
        })
    }

    /// Loads the configured main module and initializes the primary scheduler thread once.
    pub fn load(&mut self) -> Result<&ModuleRecord, VmError> {
        if !self.core.loaded {
            self.debug_load_stage("load:start");
            let configured_main_path = self.core.config.main_module.clone();
            let process_image_path = self.core.config.process_image_path().to_path_buf();
            let entry_module_path = self.core.config.entry_module_path().to_path_buf();
            let process_image = self.core.modules.load_runtime_main(
                process_image_path.clone(),
                &self.core.config,
                &mut self.core.hooks,
            )?;
            self.debug_load_stage("load:process_image_loaded");
            self.log_module_event("MODULE_LOAD", &process_image, "process_image")?;
            let configured_main_module = if configured_main_path == process_image_path {
                process_image.clone()
            } else {
                let module = self.core.modules.load_runtime_main(
                    configured_main_path.clone(),
                    &self.core.config,
                    &mut self.core.hooks,
                )?;
                self.log_module_event("MODULE_LOAD", &module, "configured_main")?;
                self.debug_load_stage("load:configured_main_loaded");
                module
            };
            let entry_module = if entry_module_path == process_image_path {
                process_image.clone()
            } else if entry_module_path == configured_main_path {
                configured_main_module.clone()
            } else {
                let module = self.core.modules.load_runtime_main(
                    entry_module_path.clone(),
                    &self.core.config,
                    &mut self.core.hooks,
                )?;
                self.log_module_event("MODULE_LOAD", &module, "entry_module")?;
                self.debug_load_stage("load:entry_module_loaded");
                module
            };
            self.ensure_supported_execution_architecture(&configured_main_module, "load")?;
            self.ensure_supported_execution_architecture(&entry_module, "load")?;
            self.debug_load_stage("load:architecture_checked");
            self.preload_startup_baseline_modules()?;
            self.debug_load_stage("load:baseline_preloaded");
            let preloads = self.core.config.preload_modules.clone();
            for preload in &preloads {
                let module = self.core.modules.load_runtime_dependency(
                    &preload,
                    &self.core.config,
                    &mut self.core.hooks,
                )?;
                self.log_module_event("MODULE_LOAD", &module, "preload")?;
            }
            self.debug_load_stage("load:preloads_loaded");
            self.reserve_process_env_footprint()?;
            self.debug_load_stage("load:process_env_reserved");
            self.core.process_env = WindowsProcessEnvironment::from_reserved(
                self.core.modules.memory(),
                self.core.arch,
            )?;
            self.debug_load_stage("load:process_env_created");
            self.core.entry_invocation = if self.core.config.uses_export_entry() {
                EntryInvocation::Export
            } else {
                EntryInvocation::NativeEntrypoint
            };
            self.core.entry_module_requires_attach = self.core.entry_invocation
                == EntryInvocation::Export
                && Self::module_looks_like_dll(&entry_module);
            self.core.entry_address = Some(self.resolve_entry_address(&entry_module)?);
            self.core.entry_arguments = self.prepare_entry_arguments(&entry_module)?;
            let runtime_process_image_path =
                if !self.core.environment_profile.machine.image_path.is_empty() {
                    self.core.environment_profile.machine.image_path.clone()
                } else {
                    process_image
                        .path
                        .as_ref()
                        .map(|path| path.to_string_lossy().to_string())
                        .unwrap_or_else(|| process_image.name.clone())
                };
            self.core.command_line = if !self
                .core
                .environment_profile
                .machine
                .command_line
                .is_empty()
            {
                self.core.environment_profile.machine.command_line.clone()
            } else if !self.core.config.command_line.is_empty() {
                self.core.config.command_line.clone()
            } else {
                runtime_process_image_path.clone()
            };
            self.core.current_directory = if !self
                .core
                .environment_profile
                .machine
                .current_directory
                .is_empty()
            {
                std::path::PathBuf::from(&self.core.environment_profile.machine.current_directory)
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
            self.core.current_directory_host = self
                .resolve_absolute_runtime_path(&self.core.current_directory.to_string_lossy())
                .unwrap_or_else(|| self.core.current_directory.clone());
            self.ensure_virtual_windows_layout()?;
            self.core.parent_process = self.build_parent_process_identity();
            let dll_path = self.build_process_dll_path();
            let tmp_directory = self.temporary_directory_path();
            self.initialize_runtime_environment_variables(&dll_path, &tmp_directory)?;
            let environment = self.runtime_environment_entries();
            self.core
                .process_env
                .configure_process_parameters_with_runtime_details_and_environment(
                    &runtime_process_image_path,
                    &self.core.command_line,
                    &self.core.current_directory.to_string_lossy(),
                    &dll_path,
                    &environment,
                )?;
            self.debug_load_stage("load:process_parameters_configured");
            self.core.process_env.sync_image_base(process_image.base);
            self.core
                .process_env
                .sync_process_heap(self.process_memory.heaps.process_heap() as u64);
            self.refresh_all_visible_bases();
            self.sync_process_environment_modules()?;
            self.debug_load_stage("load:env_modules_synced");
            self.refresh_known_data_imports()?;
            self.debug_load_stage("load:data_imports_refreshed");
            self.patch_synthetic_stubs_with_real_prologues()?;
            self.debug_load_stage("load:synthetic_prologues_patched");
            let main_thread = self
                .core
                .scheduler
                .register_main_thread_with_parameter(
                    self.core.entry_address.unwrap_or(entry_module.entrypoint),
                    self.core.entry_arguments.first().copied().unwrap_or(0),
                )
                .ok_or(VmError::RuntimeInvariant("failed to register main thread"))?;
            self.debug_load_stage("load:main_thread_registered");
            let (stack_limit, stack_top, stack_base) = {
                let memory = self.core.modules.memory_mut();
                let (stack_allocation_base, stack_top) = memory.allocate_stack()?;
                let stack_base = stack_allocation_base + memory.layout().stack_size;
                (stack_allocation_base, stack_top, stack_base)
            };
            self.debug_load_stage("load:stack_allocated");
            let stack_limit = self.register_initial_thread_stack_allocation(
                self.current_process_space_key(),
                stack_limit,
                stack_base,
                stack_top,
            )?;
            self.debug_load_stage("load:stack_registered");
            let thread_context = self
                .core
                .process_env
                .allocate_thread_teb(stack_base, stack_limit)?;
            self.debug_load_stage("load:teb_allocated");
            self.core.process_env.sync_teb_client_id(
                thread_context.teb_base,
                self.current_process_id(),
                main_thread.tid,
            );
            self.initialize_scheduler_thread_context(main_thread.tid, thread_context, stack_top)?;
            self.debug_load_stage("load:scheduler_thread_initialized");
            if self.core.entry_invocation == EntryInvocation::Export && self.core.arch.is_x86() {
                let mut registers = self
                    .core
                    .scheduler
                    .thread_snapshot(main_thread.tid)
                    .ok_or(VmError::RuntimeInvariant("main thread snapshot missing"))?
                    .registers;
                let saved_esp = registers.esp;
                let mut frame = Vec::with_capacity((self.core.entry_arguments.len() + 1) * 4);
                frame.extend_from_slice(&(self.core.native_return_sentinel as u32).to_le_bytes());
                for value in &self.core.entry_arguments {
                    frame.extend_from_slice(&(*value as u32).to_le_bytes());
                }
                let new_esp = saved_esp
                    .checked_sub(frame.len() as u64)
                    .ok_or(VmError::RuntimeInvariant("native call stack underflow"))?;
                self.core.modules.memory_mut().write(new_esp, &frame)?;
                registers.esp = new_esp;
                registers.eip = self.core.entry_address.unwrap_or(entry_module.entrypoint);
                self.core
                    .scheduler
                    .set_thread_registers(main_thread.tid, registers)
                    .ok_or(VmError::RuntimeInvariant(
                        "failed to seed x86 export bootstrap frame",
                    ))?;
            }
            self.core
                .scheduler
                .switch_to(main_thread.tid, &mut self.core.process_env)
                .ok_or(VmError::RuntimeInvariant(
                    "failed to switch scheduler to main thread",
                ))?;
            self.debug_load_stage("load:scheduler_switched");
            self.sync_native_support_state()?;
            self.debug_load_stage("load:native_support_synced");
            self.core.main_thread_tid = Some(main_thread.tid);
            self.log_thread_event(
                "THREAD_CREATE",
                main_thread.tid,
                main_thread.handle,
                self.core.entry_address.unwrap_or(entry_module.entrypoint),
                self.core.entry_arguments.first().copied().unwrap_or(0),
                "ready",
            )?;
            self.log_thread_entry_dump_if_dynamic(
                "THREAD_START_DUMP",
                "THREAD_CREATE",
                main_thread.tid,
                main_thread.handle,
                self.core.entry_address.unwrap_or(entry_module.entrypoint),
                self.core.entry_arguments.first().copied().unwrap_or(0),
                "ready",
            )?;
            self.core.main_module = Some(process_image);
            self.core.entry_module = Some(entry_module);
            for module in self
                .current_process_modules()
                .into_iter()
                .filter(|module| !module.synthetic)
            {
                self.register_module_image_allocation(self.current_process_space_key(), &module)?;
            }
            self.core.loaded = true;
        }

        Ok(self
            .core
            .main_module
            .as_ref()
            .ok_or(VmError::RuntimeInvariant("main module not set after load"))?)
    }

    /// Runs the engine and returns execution results.
    pub fn run(&mut self) -> Result<RunResult, VmError> {
        let run_started = std::time::Instant::now();
        let main_module = self.load()?.clone();
        let entrypoint = self.core.entry_address.unwrap_or(main_module.entrypoint);
        self.reset_run_observation();
        if self.unicorn_state.unicorn.is_some() {
            self.run_native_main()?;
        } else if self.core.arch.is_x64() {
            return Err(VmError::NativeExecution {
                op: "run",
                detail: "x64 execution requires a native Unicorn backend".to_string(),
            });
        } else {
            self.run_interpreter_scheduler_main()?;
        }
        if self.core.exit_code.is_none() {
            if let Some(main_tid) = self.core.main_thread_tid {
                self.core.exit_code = self.core.scheduler.thread_exit_code(main_tid).flatten();
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
        self.log_final_summary(stop_reason)?;
        self.core.api_logger.flush()?;

        let result = RunResult {
            entrypoint,
            instructions: self.core.instruction_count + self.core.emu_floor_instructions,
            stopped: true,
            exit_code: self.core.exit_code,
            stop_reason,
        };
        let wall_duration = run_started.elapsed();
        if let Err(e) = self.core.runtime_profiler.emit_report(
            wall_duration,
            result.instructions,
            result.stop_reason,
        ) {
            eprintln!("[PROFILER_ERROR] emit_report failed: {e}");
            // Don't propagate profiler errors — the run result is still valid.
        }
        Ok(result)
    }

    /// Runs the engine and returns both the basic `RunResult` and a structured `SandboxResult`
    /// suitable for JSON serialization by the sandbox `analyze` command.
    pub fn run_with_result(
        &mut self,
        sample_hash: &str,
        sample_size: u64,
        timestamp: &str,
    ) -> Result<(RunResult, crate::sandbox_result::SandboxResult), VmError> {
        use crate::sandbox_result::*;

        let run_started = std::time::Instant::now();
        self.behavior.enabled = true;

        let run_result = self.run()?;
        let execution_time_ms = run_started.elapsed().as_millis() as u64;

        let status = match run_result.stop_reason {
            RunStopReason::InstructionBudgetExhausted => status::TIMEOUT,
            RunStopReason::UnsupportedHook => status::COMPLETED,
            RunStopReason::ProcessExit
            | RunStopReason::MainThreadTerminated
            | RunStopReason::AllThreadsTerminated
            | RunStopReason::RunComplete
            | RunStopReason::SchedulerIdle
            | RunStopReason::MemoryAccessViolation => status::COMPLETED,
        };

        let arch_name = if self.core.arch.is_x64() {
            "x64"
        } else {
            "x86"
        };

        // Drain the in-memory behavior collector.
        let behavior = std::mem::take(&mut self.behavior);

        let sandbox_result = SandboxResult {
            sample_hash: sample_hash.to_string(),
            sample_size,
            arch: arch_name.to_string(),
            timestamp: timestamp.to_string(),
            execution_time_ms,
            hvm_version: env!("CARGO_PKG_VERSION").to_string(),
            status: status.to_string(),
            exit_code: run_result.exit_code,
            stop_reason: run_result.stop_reason.as_str().to_string(),
            instruction_count: run_result.instructions,
            error_message: None,
            api_calls: Vec::new(),
            network_events: behavior.network_events,
            file_operations: behavior.file_operations,
            registry_operations: behavior.registry_operations,
            process_operations: behavior.process_operations,
            dropped_files: behavior.dropped_files,
            console_output: behavior.console_output,
            pe_info: None,
        };

        Ok((run_result, sandbox_result))
    }

    /// Returns the loaded main module when the runtime has been initialized.
    pub fn main_module(&self) -> Option<&ModuleRecord> {
        self.core.main_module.as_ref()
    }

    /// Returns the loaded execution module when it differs from the process image.
    pub fn entry_module(&self) -> Option<&ModuleRecord> {
        self.core.entry_module.as_ref()
    }

    /// Returns the resolved execution address after load.
    pub fn entry_address(&self) -> Option<u64> {
        self.core.entry_address
    }

    /// Returns the prepared argument vector used for the effective entry invocation.
    pub fn entry_arguments(&self) -> &[u64] {
        &self.core.entry_arguments
    }

    /// Returns the synthetic export registry wired into the current engine.
    pub fn hooks(&self) -> &HookRegistry {
        &self.core.hooks
    }

    /// Returns the scheduler owned by the current engine.
    pub fn scheduler(&self) -> &ThreadScheduler {
        &self.core.scheduler
    }

    /// Returns the total number of instructions executed so far,
    /// including both BLOCK-hook estimates and emu_count floor contributions.
    pub fn instruction_count(&self) -> u64 {
        self.core.instruction_count + self.core.emu_floor_instructions
    }

    /// Returns the stored entrypoint address (panics if unset — should only be called after `new`).
    pub fn entrypoint(&self) -> u64 {
        self.core.entry_address.unwrap_or(0)
    }

    /// Returns mutable scheduler access for runtime hook dispatch tests.
    pub fn scheduler_mut(&mut self) -> &mut ThreadScheduler {
        &mut self.core.scheduler
    }

    /// Returns the process-environment mirror owned by the current engine.
    pub fn process_env(&self) -> &WindowsProcessEnvironment {
        &self.core.process_env
    }

    /// Returns the child-process manager owned by the current engine.
    pub fn processes(&self) -> &ProcessManager {
        &self.core.processes
    }

    /// Returns the module manager owned by the current engine.
    pub fn modules(&self) -> &ModuleManager {
        &self.core.modules
    }

    /// Returns the effective command line the Rust runtime will expose after load.
    pub fn command_line(&self) -> &str {
        &self.core.command_line
    }

    /// Returns the registered main-thread identifier once the engine has loaded.
    pub fn main_thread_tid(&self) -> Option<u32> {
        self.core.main_thread_tid
    }

    /// Returns the registered main-thread handle once the engine has loaded.
    pub fn main_thread_handle(&self) -> Option<u32> {
        let tid = self.core.main_thread_tid?;
        self.core
            .scheduler
            .thread_snapshot(tid)
            .map(|thread| thread.handle)
    }

    /// Returns the synthetic return address used to terminate the primary x86 thread cleanly.
    pub fn main_thread_exit_sentinel(&self) -> u64 {
        self.core.native_return_sentinel
    }

    /// Returns the effective current directory derived during load.
    pub fn current_directory(&self) -> &std::path::Path {
        &self.core.current_directory
    }

    /// Returns whether a native Unicorn backend is available for current-process execution.
    pub fn has_native_unicorn(&self) -> bool {
        self.unicorn_state.unicorn.is_some()
    }

    /// Returns the active Win32 last-error value mirrored into the current TEB.
    pub fn last_error(&self) -> u32 {
        self.core.last_error
    }

    /// Returns the process heap handle exposed by the runtime.
    pub fn process_heap_handle(&self) -> u32 {
        self.process_memory.heaps.process_heap()
    }

    /// Returns the heap manager owned by the current engine.
    pub fn heap_manager(&self) -> &HeapManager {
        &self.process_memory.heaps
    }

    /// Returns the device manager owned by the current engine.
    pub fn device_manager(&self) -> &DeviceManager {
        &self.dispatch.devices
    }

    /// Returns the registry manager owned by the current engine.
    pub fn registry_manager(&self) -> &RegistryManager {
        &self.core.registry
    }

    /// Returns the network manager owned by the current engine.
    pub fn network_manager(&self) -> &NetworkManager {
        &self.network_state.network
    }

    /// Returns mutable network-manager access for runtime integration tests.
    pub fn network_manager_mut(&mut self) -> &mut NetworkManager {
        &mut self.network_state.network
    }

    /// Returns the crypto manager owned by the current engine.
    pub fn crypto_manager(&self) -> &CryptoManager {
        &self.network_state.crypto
    }

    /// Returns mutable crypto-manager access for runtime integration tests.
    pub fn crypto_manager_mut(&mut self) -> &mut CryptoManager {
        &mut self.network_state.crypto
    }

    /// Updates the active Win32 last-error value and mirrors it into the current TEB.
    pub fn set_last_error(&mut self, value: u32) {
        self.core.last_error = value;
        self.core.process_env.sync_last_error(value);
        let teb_last_error = self.core.process_env.current_teb()
            + self.core.process_env.offsets().teb_last_error as u64;
        if self
            .core
            .modules
            .memory()
            .is_range_mapped(teb_last_error, 4)
        {
            let _ = self
                .core
                .modules
                .memory_mut()
                .write(teb_last_error, &value.to_le_bytes());
        } else {
            let _ = self.sync_native_support_state();
        }
    }

    fn record_instruction_retired(&mut self) {
        self.record_instructions_retired(1);
    }

    fn record_instructions_retired(&mut self, count: u64) {
        if count == 0 {
            return;
        }
        self.core.instruction_count = self.core.instruction_count.wrapping_add(count);
        let since = self
            .core
            .instructions_since_time_advance
            .wrapping_add(count);
        if since >= EMULATED_TIME_PROGRESS_INTERVAL_INSTRUCTIONS {
            let advances = since / EMULATED_TIME_PROGRESS_INTERVAL_INSTRUCTIONS;
            self.core.instructions_since_time_advance =
                since % EMULATED_TIME_PROGRESS_INTERVAL_INSTRUCTIONS;
            self.dispatch.time.advance(advances);
        } else {
            self.core.instructions_since_time_advance = since;
        }
    }

    fn remaining_run_budget(&self) -> u64 {
        self.core
            .config
            .max_instructions
            .max(1)
            .saturating_sub(self.core.instruction_count)
    }

    /// Binds one hook stub explicitly so runtime dispatch tests do not depend on sample imports.
    pub fn bind_hook_for_test(&mut self, module: &str, function: &str) -> u64 {
        let stub = self.core.hooks.bind_stub(module, function);
        let page = stub & !(PAGE_SIZE - 1);
        let page_was_mapped = self.core.modules.memory().is_range_mapped(page, PAGE_SIZE);
        if !page_was_mapped {
            self.core
                .modules
                .memory_mut()
                .map_region(
                    page,
                    PAGE_SIZE,
                    crate::memory::manager::PROT_READ | crate::memory::manager::PROT_EXEC,
                    "hook:test_stub",
                )
                .expect("failed to map hook test stub page");
        }
        self.core
            .modules
            .memory_mut()
            .write(
                stub,
                &[
                    0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                    0xCC, 0xCC, 0xCC,
                ],
            )
            .expect("failed to write hook test stub bytes");
        if let (Some(unicorn), Some(uc)) = (
            self.unicorn_state.unicorn.as_deref(),
            self.unicorn_state.unicorn_handle,
        ) {
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
        self.core
            .modules
            .memory_mut()
            .reserve(PAGE_SIZE, Some(preferred), "native:test_page", false)
            .map_err(VmError::from)
    }

    /// Writes raw machine code or test bytes into the emulated address space.
    pub fn write_test_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), VmError> {
        self.core
            .modules
            .memory_mut()
            .write(address, bytes)
            .map_err(VmError::from)?;
        self.propagate_file_mapping_write(self.current_process_space_key(), address, bytes)
    }

    /// Refreshes visible bases for all currently loaded modules, applying any
    /// configured `module_visible_bases` overrides before the PEB/LDR structures
    /// are materialized into guest memory.  After updating bases, re-registers
    /// every real export with the hook dispatcher so both mapped-base and
    /// visible-base address variants are bound.
    fn refresh_all_visible_bases(&mut self) {
        let bases: Vec<u64> = self
            .core
            .modules
            .loaded_modules()
            .iter()
            .map(|m| m.base)
            .collect();
        for base in &bases {
            self.refresh_module_visible_base(*base);
        }
        // Fix up import thunk values in visible aliases after all bases are set.
        // Import thunks are not covered by PE relocation tables, so they need
        // explicit adjustment from mapped to visible addresses.
        let names: Vec<String> = self.core.modules.module_names();
        for name in &names {
            self.core
                .modules
                .fixup_visible_alias_import_thunks(name, &self.core.hooks);
        }
        self.core
            .modules
            .rebind_all_real_exports(&mut self.core.hooks);
    }

    pub(super) fn refresh_module_visible_base(&mut self, mapped_base: u64) -> Option<ModuleRecord> {
        let module = self.core.modules.get_by_base(mapped_base).cloned()?;
        let configured_visible_base = self
            .core
            .environment_profile
            .module_visible_bases
            .get(&module.name.to_ascii_lowercase())
            .copied()
            .filter(|visible_base| *visible_base != 0)
            .unwrap_or(module.visible_base);
        if configured_visible_base == module.visible_base {
            return Some(module);
        }
        if !self
            .core
            .modules
            .set_visible_base(mapped_base, configured_visible_base)
        {
            return Some(module);
        }
        // After the visible base changes, the visible alias was created from
        // fresh file bytes.  Fix up import thunks (not covered by PE reloc
        // tables) so the visible alias IAT mirrors the mapped-image IAT, and
        // re-bind all real exports so the hook registry learns the new
        // visible-base address variants.
        let storage_name = self
            .core
            .modules
            .get_by_base(mapped_base)
            .map(|m| m.name.clone())
            .unwrap_or_default();
        if !storage_name.is_empty() {
            self.core
                .modules
                .fixup_visible_alias_import_thunks(&storage_name, &self.core.hooks);
            self.core
                .modules
                .rebind_all_real_exports(&mut self.core.hooks);
        }
        self.core.modules.get_by_base(mapped_base).cloned()
    }

    /// Executes one x86 native call using the current main-thread stack frame and returns EAX.
    pub fn call_native_for_test(&mut self, address: u64, args: &[u64]) -> Result<u64, VmError> {
        self.load()?;
        if self.core.hooks.is_bound_address(address) {
            return self.dispatch_bound_stub(address, args);
        }
        if self.core.arch.is_x64() {
            if self.unicorn_state.unicorn.is_some() && !unicorn_context_active() {
                self.call_x64_native_with_unicorn(address, args)
            } else {
                Err(VmError::NativeExecution {
                    op: "run",
                    detail: "x64 execution requires a native Unicorn backend".to_string(),
                })
            }
        } else if self.unicorn_state.unicorn.is_some() && !unicorn_context_active() {
            self.call_x86_native_with_unicorn(address, args)
        } else {
            self.call_x86_native_interpreter(address, args)
        }
    }

    /// Flushes buffered API and console logs so integration tests can inspect emitted traces.
    pub fn flush_api_logs_for_test(&mut self) -> Result<(), VmError> {
        self.core.api_logger.flush()
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
        self.core.stop_reason = None;
        self.core.process_exit_requested = false;
        self.trace.native_trace.reset();
        self.core.next_checkpoint_index = 0;
    }

    fn check_observation_checkpoints(&mut self) -> Result<(), VmError> {
        while self.core.next_checkpoint_index < self.core.observation_checkpoints.len() {
            let target_icount = self.core.observation_checkpoints[self.core.next_checkpoint_index];
            if self.core.instruction_count < target_icount {
                break;
            }
            self.dump_observation_checkpoint(target_icount)?;
            self.core.next_checkpoint_index += 1;
        }
        Ok(())
    }

    fn dump_observation_checkpoint(&mut self, target_icount: u64) -> Result<(), VmError> {
        let memory = self.core.modules.memory();
        let dump_regions: &[(&str, u64, usize)] = &[
            ("oep_header_32b", 0x402316, 32),
            ("kernel32_base_slot", 0x402738, 4),
            ("load_library_slot", 0x402750, 4),
            ("get_proc_addr_slot", 0x402763, 4),
            ("close_handle_slot", 0x402773, 4),
            ("state_block_12b", 0x40269C, 12),
        ];
        let mut fields = Map::new();
        fields.insert(
            "target_icount".to_string(),
            serde_json::json!(target_icount),
        );
        fields.insert(
            "actual_icount".to_string(),
            serde_json::json!(self.core.instruction_count),
        );
        for &(label, address, size) in dump_regions {
            let hex = memory
                .read(address, size)
                .map(|bytes| Self::format_runtime_bytes(&bytes))
                .unwrap_or_else(|_| "<unreadable>".to_string());
            fields.insert(label.to_string(), serde_json::json!(hex));
        }
        self.log_runtime_event_immediate("OBSERVATION_CHECKPOINT", fields)
    }

    fn maybe_emit_debug_pc_probe(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        address: u64,
    ) -> Result<(), VmError> {
        if !self.core.debug_pc_probes.contains(&address) {
            return Ok(());
        }

        let registers = self.capture_unicorn_thread_registers(api, uc)?;
        let stack_words = self.capture_unicorn_stack_words(api, uc, &registers)?;
        let unicorn = unsafe { api.bind(uc) };
        let mut fields = Map::new();
        fields.insert("pc".to_string(), json!(address));
        self.add_address_ref_fields(&mut fields, "pc", address);
        if let Ok(bytes) = unicorn.mem_read(address, 16) {
            fields.insert(
                "pc_bytes".to_string(),
                json!(Self::format_runtime_bytes(&bytes)),
            );
        }
        fields.insert(
            "registers".to_string(),
            Self::register_map_value(&registers),
        );
        fields.insert(
            "register_refs".to_string(),
            self.register_ref_map_value(&registers),
        );
        fields.insert(
            "stack_words".to_string(),
            Self::word_map_value(&stack_words),
        );

        let register_points = if self.core.arch.is_x86() {
            [
                ("eax", registers.eax),
                ("ebx", registers.ebx),
                ("ecx", registers.ecx),
                ("edx", registers.edx),
                ("esi", registers.esi),
                ("edi", registers.edi),
                ("ebp", registers.ebp),
                ("esp", registers.esp),
            ]
            .to_vec()
        } else {
            [
                ("rax", registers.rax),
                ("rbx", registers.rbx),
                ("rcx", registers.rcx),
                ("rdx", registers.rdx),
                ("r8", registers.r8),
                ("r9", registers.r9),
                ("rsi", registers.rsi),
                ("rdi", registers.rdi),
                ("rbp", registers.rbp),
                ("rsp", registers.rsp),
            ]
            .to_vec()
        };
        for (name, value) in register_points {
            if value == 0 {
                continue;
            }
            self.add_address_ref_fields(&mut fields, name, value);
            match unicorn.mem_read(value, 16) {
                Ok(bytes) => {
                    fields.insert(
                        format!("{name}_bytes"),
                        json!(Self::format_runtime_bytes(&bytes)),
                    );
                }
                Err(_) => {
                    fields.insert(format!("{name}_bytes"), json!("<unreadable>"));
                }
            }
            if self.core.arch.is_x64() {
                for offset in [0x0u64, 0x8, 0x10, 0x18, 0x28, 0x38, 0x40, 0x58] {
                    let field_name = format!("{name}_qword_0x{offset:X}");
                    if let Ok(bytes) = unicorn.mem_read(value.saturating_add(offset), 8) {
                        let field_value = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
                        fields.insert(field_name.clone(), json!(field_value));
                        if field_value != 0 {
                            self.add_address_ref_fields(&mut fields, &field_name, field_value);
                        }
                    }
                }
                for offset in [0x38u64, 0x3C, 0x40, 0x58] {
                    let field_name = format!("{name}_dword_0x{offset:X}");
                    if let Ok(bytes) = unicorn.mem_read(value.saturating_add(offset), 4) {
                        let field_value = u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]));
                        fields.insert(field_name, json!(field_value));
                    }
                }
            }
        }

        self.log_runtime_event_immediate("EXEC_PROBE", fields)
    }

    fn preload_startup_baseline_modules(&mut self) -> Result<(), VmError> {
        for module_name in STARTUP_BASELINE_MODULES {
            let existing = self.core.modules.get_loaded(module_name).cloned();
            let module = self.core.modules.load_runtime_dependency(
                module_name,
                &self.core.config,
                &mut self.core.hooks,
            )?;
            self.objects.startup_pinned_modules.insert(module.base);
            if existing.is_none() {
                self.log_module_event("MODULE_LOAD", &module, "startup_baseline")?;
            }
        }
        Ok(())
    }

    /// Overwrites synthetic hook stub bytes with real function prologues read from
    /// on-disk DLLs.  This makes prologue-based integrity checks pass without having
    /// to load real DLLs into the emulated address space (which would trigger import
    /// resolution cascades and memory exhaustion).
    fn patch_synthetic_stubs_with_real_prologues(&mut self) -> Result<(), VmError> {
        if self.core.config.prologue_source_paths.is_empty() {
            return Ok(());
        }
        let bound_addresses = self.core.hooks.bound_addresses();
        let mut patches: Vec<(u64, Vec<u8>)> = Vec::new();
        for address in bound_addresses {
            let Some((module, function)) = self.core.hooks.binding_for_address(address) else {
                continue;
            };
            let real_bytes = read_real_prologue(
                module,
                function,
                &self.core.config.prologue_source_paths,
                16,
            );
            if let Some(bytes) = real_bytes {
                patches.push((address, bytes));
            }
        }
        for (address, bytes) in patches {
            let _ = self.core.modules.memory_mut().write(address, &bytes);
        }
        Ok(())
    }

    fn request_thread_yield(&mut self, _reason: &str, preserve_api_frame: bool) {
        self.dispatch.request_thread_yield(preserve_api_frame);
    }

    fn handle_requested_thread_yield(&mut self) {
        let _profile = self
            .core
            .runtime_profiler
            .start_scope("yield.handle_requested");
        let current_tick = self.dispatch.time.current().tick_ms;
        if !self.core.scheduler.has_ready_threads() {
            if let Some(next_tick) = self.core.scheduler.next_wake_tick() {
                if next_tick > current_tick {
                    self.dispatch.time.advance(next_tick - current_tick);
                }
            }
        }
        {
            let _profile = self
                .core
                .runtime_profiler
                .start_scope("scheduler.poll_blocked_threads");
            self.core
                .scheduler
                .poll_blocked_threads(self.dispatch.time.current().tick_ms);
        }
        if let Some(tid) = self.core.scheduler.current_tid() {
            let _profile = self
                .core
                .runtime_profiler
                .start_scope("scheduler.switch_to");
            let _ = self
                .core
                .scheduler
                .switch_to(tid, &mut self.core.process_env);
        }
    }
}

mod dispatch;

mod scheduler_methods;

fn parse_debug_pc_probes_from_env() -> BTreeSet<u64> {
    let mut probes = BTreeSet::new();
    let Ok(raw) = std::env::var("HVM_DEBUG_PC_PROBES") else {
        return probes;
    };
    for token in raw.split(|ch: char| matches!(ch, ',' | ';' | ' ' | '\n' | '\t')) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let parsed = if let Some(hex) = token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16).ok()
        } else {
            token.parse::<u64>().ok()
        };
        if let Some(address) = parsed {
            probes.insert(address);
        }
    }
    probes
}

impl Drop for VirtualExecutionEngine {
    fn drop(&mut self) {
        self.close_unicorn_session();
    }
}

#[cfg(test)]
mod tests;

thread_local! {
    static ACTIVE_UNICORN_CONTEXT: Cell<*mut UnicornRunContext> = const { Cell::new(std::ptr::null_mut()) };
    // Bound API hooks run after the current emu_start slice exits, so they need
    // a second thread-local handle to the live Unicorn session.
    static ACTIVE_HOOK_UNICORN_CONTEXT: Cell<Option<HookUnicornContext>> = const { Cell::new(None) };
}

fn unicorn_context_active() -> bool {
    ACTIVE_UNICORN_CONTEXT.with(|slot| !slot.get().is_null())
}

#[derive(Clone, Copy)]
struct HookUnicornContext {
    engine: *mut VirtualExecutionEngine,
    api: *const UnicornApi,
    uc: *mut UcEngine,
}

mod native_trace_types;
use native_trace_types::*;

fn flush_unicorn_pending_writes(
    state: &mut UnicornRunContext,
    uc: *mut UcEngine,
) -> Result<(), VmError> {
    if state.pending_writes.is_empty() {
        return Ok(());
    }
    let api = unsafe { &*state.api };
    let unicorn = unsafe { api.bind(uc) };
    let engine = unsafe { &mut *state.engine };
    let pending_ranges = state.pending_writes.len() as u64;
    let pending_bytes = state.pending_write_bytes;
    let profiler_enabled = engine.core.runtime_profiler.enabled();
    if profiler_enabled {
        engine
            .core
            .runtime_profiler
            .add_counter("unicorn.flush_pending_writes.calls", 1);
        engine.core.runtime_profiler.add_counter(
            "unicorn.flush_pending_writes.pending_ranges",
            pending_ranges,
        );
        engine
            .core
            .runtime_profiler
            .add_counter("unicorn.flush_pending_writes.pending_bytes", pending_bytes);
        engine.core.runtime_profiler.set_counter_max(
            "unicorn.flush_pending_writes.max_pending_ranges",
            pending_ranges,
        );
        engine.core.runtime_profiler.set_counter_max(
            "unicorn.flush_pending_writes.max_pending_bytes",
            pending_bytes,
        );
    }
    let _profile = engine
        .core
        .runtime_profiler
        .start_scope("unicorn.flush_pending_writes");
    let pending = std::mem::take(&mut state.pending_writes);
    state.pending_write_bytes = 0;
    state.suppress_mem_write_hook = true;
    let flush_pc = if engine.core.arch.is_x86() {
        unicorn.reg_read(UC_X86_REG_EIP).ok()
    } else {
        unicorn.reg_read(UC_X86_REG_RIP).ok()
    };
    let log_native_code_write = engine.core.api_logger.writes_marker("NATIVE_CODE_WRITE");
    let result = (|| -> Result<(), VmError> {
        for (address, size) in pending {
            if profiler_enabled {
                engine
                    .core
                    .runtime_profiler
                    .add_counter("unicorn.flush_pending_writes.ranges", 1);
                engine
                    .core
                    .runtime_profiler
                    .add_counter("unicorn.flush_pending_writes.range_bytes", size as u64);
                if size == 1 {
                    engine
                        .core
                        .runtime_profiler
                        .add_counter("unicorn.flush_pending_writes.single_byte_ranges", 1);
                }
            }
            let end = address.saturating_add(size as u64);
            let mut chunk_address = address;
            while chunk_address < end {
                let next_page =
                    ((chunk_address & !(PAGE_SIZE - 1)).saturating_add(PAGE_SIZE)).min(end);
                let chunk_size = next_page.saturating_sub(chunk_address) as usize;
                if profiler_enabled {
                    engine
                        .core
                        .runtime_profiler
                        .add_counter("unicorn.flush_pending_writes.page_chunks", 1);
                    engine.core.runtime_profiler.add_counter(
                        "unicorn.flush_pending_writes.page_chunk_bytes",
                        chunk_size as u64,
                    );
                }
                let mut bytes = SmallVec::<[u8; 16]>::with_capacity(chunk_size);
                bytes.resize(chunk_size, 0);
                unicorn
                    .mem_read_into(chunk_address, bytes.as_mut_slice())
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_mem_read(writeback)",
                        detail: format_writeback_error_detail(
                            &detail,
                            address,
                            size,
                            chunk_address,
                            chunk_size,
                            flush_pc,
                        ),
                    })?;
                let exec_chunk = if log_native_code_write {
                    let perms = {
                        let _profile = engine
                            .core
                            .runtime_profiler
                            .start_scope("unicorn.flush_pending_writes.find_region");
                        engine
                            .core
                            .modules
                            .memory()
                            .find_region(chunk_address, chunk_size as u64)
                            .map(|region| region.perms)
                    };
                    let Some(perms) = perms else {
                        engine
                            .core
                            .runtime_profiler
                            .add_counter("unicorn.flush_pending_writes.unmapped_chunks", 1);
                        chunk_address = next_page;
                        continue;
                    };
                    perms & PROT_EXEC != 0
                } else {
                    false
                };
                if exec_chunk {
                    engine
                        .core
                        .runtime_profiler
                        .add_counter("unicorn.flush_pending_writes.exec_chunks", 1);
                    engine.core.runtime_profiler.add_counter(
                        "unicorn.flush_pending_writes.exec_chunk_bytes",
                        chunk_size as u64,
                    );
                    let preview_len = bytes.len().min(16);
                    {
                        let _profile = engine
                            .core
                            .runtime_profiler
                            .start_scope("unicorn.flush_pending_writes.log_native_code_write");
                        engine.log_native_code_write(
                            chunk_address,
                            chunk_size,
                            &bytes[..preview_len],
                        )?;
                    }
                }
                {
                    let _profile = engine
                        .core
                        .runtime_profiler
                        .start_scope("unicorn.flush_pending_writes.write_mirror");
                    match engine
                        .core
                        .modules
                        .memory_mut()
                        .write_mirror_contiguous(chunk_address, &bytes)
                    {
                        Ok(()) => {}
                        Err(crate::error::MemoryError::MissingRegion { .. }) => {
                            engine
                                .core
                                .runtime_profiler
                                .add_counter("unicorn.flush_pending_writes.unmapped_chunks", 1);
                            chunk_address = next_page;
                            continue;
                        }
                        Err(error) => return Err(VmError::from(error)),
                    }
                }
                {
                    let _profile = engine
                        .core
                        .runtime_profiler
                        .start_scope("unicorn.flush_pending_writes.visible_alias_writeback");
                    engine
                        .core
                        .modules
                        .mirror_write_into_visible_alias(chunk_address, &bytes)
                        .map_err(VmError::from)?;
                }
                {
                    let _profile = engine
                        .core
                        .runtime_profiler
                        .start_scope("unicorn.flush_pending_writes.propagate_file_mapping_write");
                    engine.propagate_file_mapping_write(
                        engine.current_process_space_key(),
                        chunk_address,
                        &bytes,
                    )?;
                }
                chunk_address = next_page;
            }
        }
        Ok(())
    })();
    state.suppress_mem_write_hook = false;
    result
}

#[cfg(test)]
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

#[allow(dead_code)]
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
    // Only flush when writes are actually pending — avoids 9M+ no-op calls
    if !state.pending_writes.is_empty() {
        if let Err(error) = flush_unicorn_pending_writes(state, uc) {
            state.callback_error = Some(error);
            let api = &*state.api;
            let unicorn = unsafe { api.bind(uc) };
            let _ = unicorn.emu_stop();
            return;
        }
    }
    let engine = &mut *state.engine;
    let api = &*state.api;
    let unicorn = unsafe { api.bind(uc) };
    engine.record_instruction_retired();
    if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
        if let Some(module) = engine.entry_module().or_else(|| engine.main_module()) {
            if module
                .name
                .eq_ignore_ascii_case("d2727b626d299d4839fbaf2034949948")
            {
                let rva = address.saturating_sub(module.base);
                if (0xEC99..=0xECE5).contains(&rva)
                    || (0x114F0..=0x11570).contains(&rva)
                    || (0x16D3C..=0x16DD5).contains(&rva)
                {
                    eprintln!("[TRACE_IP] pc=0x{address:X} rva=0x{rva:X}");
                }
            }
        }
    }
    if address == engine.core.native_return_sentinel {
        let _ = unicorn.emu_stop();
        return;
    }
    if let Err(error) = engine.maybe_recover_mfc42u_cabinet_module_base(api, uc, address) {
        state.callback_error = Some(error);
        let _ = unicorn.emu_stop();
        return;
    }
    if let Err(error) = engine.maybe_recover_mfc42u_native_resolver_argument(api, uc, address) {
        state.callback_error = Some(error);
        let _ = unicorn.emu_stop();
        return;
    }
    if let Err(error) = engine.maybe_emit_debug_pc_probe(api, uc, address) {
        state.callback_error = Some(error);
        let _ = unicorn.emu_stop();
        return;
    }
    match engine.dispatch_unicorn_non_executable_module_address(
        api,
        uc,
        address,
        &mut state.pending_protected_fetch,
    ) {
        Ok(true) => {
            let _ = unicorn.emu_stop();
            return;
        }
        Ok(false) => {}
        Err(error) => {
            state.callback_error = Some(error);
            let _ = unicorn.emu_stop();
            return;
        }
    }
    match engine.maybe_log_observed_real_export_call(api, uc, address) {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            state.callback_error = Some(error);
            let _ = unicorn.emu_stop();
            return;
        }
    }
    if address & 0xF != 0 {
        return;
    }

    match engine.dispatch_unicorn_bound_stub(api, uc, address) {
        Ok(true) => {
            let _ = unicorn.emu_stop();
        }
        Ok(false) => {}
        Err(error) => {
            state.callback_error = Some(error);
            let _ = unicorn.reg_write(
                if engine.core.arch.is_x86() {
                    UC_X86_REG_EIP
                } else {
                    UC_X86_REG_RIP
                },
                engine.core.native_return_sentinel,
            );
            let _ = unicorn.emu_stop();
        }
    }
}

unsafe extern "C" fn unicorn_intr_hook(uc: *mut UcEngine, intno: u32, _user_data: *mut c_void) {
    let state_ptr = ACTIVE_UNICORN_CONTEXT.with(|slot| slot.get());
    if state_ptr.is_null() {
        return;
    }
    let state = &mut *state_ptr;
    if state.callback_error.is_some() || state.pending_fault.is_some() {
        return;
    }
    if let Err(error) = flush_unicorn_pending_writes(state, uc) {
        state.callback_error = Some(error);
        let api = &*state.api;
        let unicorn = unsafe { api.bind(uc) };
        let _ = unicorn.emu_stop();
        return;
    }

    let engine = &mut *state.engine;
    let api = &*state.api;
    let unicorn = unsafe { api.bind(uc) };
    let pc_reg = if engine.core.arch.is_x86() {
        UC_X86_REG_EIP
    } else {
        UC_X86_REG_RIP
    };
    let pc = match unicorn.reg_read(pc_reg) {
        Ok(value) => value,
        Err(detail) => {
            state.callback_error = Some(VmError::NativeExecution {
                op: "uc_reg_read(pc)",
                detail,
            });
            let _ = unicorn.emu_stop();
            return;
        }
    };

    match intno {
        X86_BREAKPOINT_VECTOR | UNICORN_EXCP_DEBUG => {
            state.pending_fault = Some(UnicornFault::cpu_exception(STATUS_BREAKPOINT, pc));
            let _ = unicorn.emu_stop();
        }
        0x29 => {
            // __fastfail (int 0x29) — Windows security check failure.
            // Terminate the thread gracefully rather than propagating an error.
            state.pending_fault =
                Some(UnicornFault::cpu_exception(STATUS_STACK_BUFFER_OVERRUN, pc));
            let _ = unicorn.emu_stop();
        }
        _ => {
            state.callback_error = Some(VmError::NativeExecution {
                op: "interrupt",
                detail: format!("unsupported Unicorn interrupt 0x{intno:X} at pc=0x{pc:X}"),
            });
            let _ = unicorn.emu_stop();
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
    let unicorn = unsafe { api.bind(uc) };

    // Flush accumulated writes before any engine-memory reads in dispatch paths
    if !state.pending_writes.is_empty() {
        if let Err(error) = flush_unicorn_pending_writes(state, uc) {
            state.callback_error = Some(error);
            let _ = unicorn.emu_stop();
            return;
        }
    }

    // Estimate instruction count from block byte size. Dedup ensures
    // each unique (address, size) block is counted exactly once per time slice.
    let estimated_instructions = if size > 0 {
        let avg_insn_size: u64 = if engine.core.arch.is_x64() { 4 } else { 3 };
        let s = (size as u64).max(1);
        (s + avg_insn_size - 1) / avg_insn_size
    } else {
        1u64
    };
    engine.record_instructions_retired(estimated_instructions);

    if address == engine.core.native_return_sentinel {
        let _ = unicorn.emu_stop();
        return;
    }

    if let Err(error) = engine.maybe_recover_mfc42u_cabinet_module_base(api, uc, address) {
        state.callback_error = Some(error);
        let _ = unicorn.emu_stop();
        return;
    }
    if let Err(error) = engine.maybe_recover_mfc42u_native_resolver_argument(api, uc, address) {
        state.callback_error = Some(error);
        let _ = unicorn.emu_stop();
        return;
    }
    if !engine.core.debug_pc_probes.is_empty() {
        if let Err(error) = engine.maybe_emit_debug_pc_probe(api, uc, address) {
            state.callback_error = Some(error);
            let _ = unicorn.emu_stop();
            return;
        }
    }
    match engine.maybe_log_observed_real_export_call(api, uc, address) {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            state.callback_error = Some(error);
            let _ = unicorn.emu_stop();
            return;
        }
    }
    // Bound stubs (synthetic API hook addresses) are always at block starts
    // since they are CALL/JMP targets. Alignment check is a cheap pre-filter.
    if address & 0xF == 0 {
        match engine.dispatch_unicorn_bound_stub(api, uc, address) {
            Ok(true) => {
                let _ = unicorn.emu_stop();
                return;
            }
            Ok(false) => {}
            Err(error) => {
                state.callback_error = Some(error);
                let _ = unicorn.reg_write(
                    if engine.core.arch.is_x86() {
                        crate::runtime::unicorn::UC_X86_REG_EIP
                    } else {
                        crate::runtime::unicorn::UC_X86_REG_RIP
                    },
                    engine.core.native_return_sentinel,
                );
                let _ = unicorn.emu_stop();
                return;
            }
        }
    }
    // Only capture registers + stack words if native trace sampling is enabled
    let sampling_enabled = engine.core.api_logger.native_trace_sampling_enabled();
    if sampling_enabled {
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
                let _ = unicorn.emu_stop();
                return;
            }
        }
    }
    if sampling_enabled {
        let latest_snapshot = state.recent_blocks.back().cloned();
        if let Err(error) = engine.log_native_block(address, size, latest_snapshot.as_ref()) {
            state.callback_error = Some(error);
            let _ = unicorn.emu_stop();
            return;
        }
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
    let engine = &mut *state.engine;
    let size = size as usize;
    // Batch profiler updates — only update counters when profiler is enabled
    let profiler_enabled = engine.core.runtime_profiler.enabled();
    if profiler_enabled {
        engine
            .core
            .runtime_profiler
            .add_counter("unicorn.mem_write_hook.calls", 1);
        engine
            .core
            .runtime_profiler
            .add_counter("unicorn.mem_write_hook.bytes", size as u64);
    }
    state.pending_write_bytes = state.pending_write_bytes.saturating_add(size as u64);
    // Fast path: coalesce with the last pending write if contiguous
    if let Some((previous_address, previous_size)) = state.pending_writes.last_mut() {
        let previous_end = previous_address.saturating_add(*previous_size as u64);
        if previous_end == address {
            *previous_size = previous_size.saturating_add(size);
            return;
        }
    }
    state.pending_writes.push((address, size));
    if profiler_enabled {
        engine
            .core
            .runtime_profiler
            .add_counter("unicorn.mem_write_hook.ranges_pushed", 1);
        engine.core.runtime_profiler.set_counter_max(
            "unicorn.mem_write_hook.max_pending_ranges",
            state.pending_writes.len() as u64,
        );
        engine.core.runtime_profiler.set_counter_max(
            "unicorn.mem_write_hook.max_pending_bytes",
            state.pending_write_bytes,
        );
    }
    let _ = uc;
}

unsafe extern "C" fn unicorn_mem_read_hook(
    _uc: *mut UcEngine,
    _mem_type: i32,
    _address: u64,
    _size: i32,
    _value: i64,
    _user_data: *mut c_void,
) {
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
    let unicorn = unsafe { api.bind(uc) };
    if mem_type == crate::runtime::unicorn::UC_MEM_FETCH_PROT
        && state.pending_protected_fetch.is_some()
    {
        let _ = unicorn.emu_stop();
        return true;
    }
    if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some()
        && mem_type == crate::runtime::unicorn::UC_MEM_FETCH_PROT
    {
        if let Some(module) = engine.entry_module().or_else(|| engine.main_module()) {
            if module
                .name
                .eq_ignore_ascii_case("d2727b626d299d4839fbaf2034949948")
            {
                let current_pc = unicorn
                    .reg_read(if engine.core.arch.is_x86() {
                        UC_X86_REG_EIP
                    } else {
                        UC_X86_REG_RIP
                    })
                    .unwrap_or(0);
                let current_owner = engine
                    .core
                    .modules
                    .get_by_address(current_pc)
                    .map(|record| {
                        format!(
                            "{}@0x{:X}+0x{:X}",
                            record.name,
                            record.base,
                            current_pc.saturating_sub(record.base)
                        )
                    })
                    .unwrap_or_else(|| "none".to_string());
                let target_owner = engine
                    .core
                    .modules
                    .get_by_address(address)
                    .map(|record| {
                        format!(
                            "{}@0x{:X}+0x{:X} exec={} synthetic={}",
                            record.name,
                            record.base,
                            address.saturating_sub(record.base),
                            record.allow_execution,
                            record.synthetic
                        )
                    })
                    .unwrap_or_else(|| "none".to_string());
                let binding = engine
                    .core
                    .hooks
                    .binding_for_address(address)
                    .map(|(module_name, function_name)| format!("{module_name}!{function_name}"))
                    .unwrap_or_else(|| "none".to_string());
                let has_definition = engine.core.hooks.signature_for_address(address).is_some();
                eprintln!(
                    "[D2727_FETCH_PROT] pc=0x{current_pc:X} current_owner={current_owner} address=0x{address:X} target_owner={target_owner} binding={binding} has_def={has_definition}"
                );
            }
        }
    }

    // --- Intercept execution faults in real DLL memory (memory-only mode) ---
    // Non-whitelisted real DLLs (system DLLs) are mapped into memory with
    // execute permission stripped so malware can still read their bytes for
    // anti-hook detection. When execution attempts to run code in these
    // regions, UC_MEM_FETCH_PROT fires.
    if mem_type == crate::runtime::unicorn::UC_MEM_FETCH_PROT {
        match engine.classify_protected_fetch(api, uc, address) {
            ProtectedFetchDecision::DispatchBound { address } => {
                // Defer the actual hook dispatch until emu_start returns.
                state.pending_protected_fetch =
                    Some(PendingProtectedFetchAction::DispatchBound { address });
                let _ = unicorn.emu_stop();
                return true;
            }
            ProtectedFetchDecision::SimulateReturn { address, binding } => {
                state.pending_protected_fetch =
                    Some(PendingProtectedFetchAction::SimulateReturn { address, binding });
                let _ = unicorn.emu_stop();
                return true;
            }
            ProtectedFetchDecision::StaleFetchIgnore => {
                let _ = unicorn.emu_stop();
                return true;
            }
            ProtectedFetchDecision::RaiseFault => {}
        }
    }

    let cleared = engine.consume_guard_pages_on_access(
        engine.current_process_space_key(),
        address,
        size as usize,
    );
    let had_guard_pages = !cleared.is_empty();
    for &(base, size, protect) in &cleared {
        let perms = VirtualExecutionEngine::perms_from_page_protect(protect).unwrap_or(0);
        if let Err(detail) = unicorn.mem_protect(base, size, unicorn_prot(perms)) {
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
        .map(|snapshot| {
            if engine.core.arch.is_x86() {
                snapshot.eip
            } else {
                snapshot.rip
            }
        })
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
        state.pending_fault = Some(UnicornFault::memory_access(
            access,
            address,
            size as usize,
            pc,
        ));
        let _ = unicorn.emu_stop();
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
    let stack_guard_access = access != UnicornFaultAccess::Execute
        && engine
            .current_thread_snapshot()
            .map(|thread| {
                let guard_base = thread.stack_limit.saturating_sub(PAGE_SIZE);
                let access_end = address.saturating_add((size as usize).max(1) as u64);
                thread.stack_limit != 0 && address < thread.stack_limit && guard_base < access_end
            })
            .unwrap_or(false);
    if stack_guard_access {
        state.pending_fault = Some(UnicornFault::memory_access(
            access,
            address,
            size as usize,
            pc,
        ));
        let _ = unicorn.emu_stop();
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
    let unicorn = unsafe { api.bind(uc) };
    let pc_reg = if engine.core.arch.is_x86() {
        UC_X86_REG_EIP
    } else {
        UC_X86_REG_RIP
    };
    let pc = match unicorn.reg_read(pc_reg) {
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
    // Log NULL_CALL to human-readable API log before the eprintln diagnostics
    {
        let is_null_call =
            address == 0 || (access == UnicornFaultAccess::Execute && address < 0x10000);
        if is_null_call {
            if let Some(ref regs) = registers {
                let _ = engine.log_null_call_fault(pc, address, regs);
            }
        }
    }

    // Handle null-pointer execution faults: diagnose and simulate return
    if address == 0 || (access == UnicornFaultAccess::Execute && address < 0x10000) {
        if let Some(ref regs) = registers {
            let is_x86 = engine.core.arch.is_x86();
            // Read architecture-appropriate registers for diagnostics
            let (sp, ret_reg, cx, dx) = if is_x86 {
                (regs.esp, regs.eax, regs.ecx, regs.edx)
            } else {
                (regs.rsp, regs.rax, regs.rcx, regs.rdx)
            };
            let (si, _di) = if is_x86 {
                (regs.esi, regs.edi)
            } else {
                (regs.rsi, regs.rdi)
            };
            let (r8, r9) = if is_x86 {
                (regs.ebp, regs.ebx) // x86: reuse ebp/ebx for diagnostic slots
            } else {
                (regs.r8, regs.r9)
            };
            eprintln!(
                "[NULL_CALL] pc=0x{pc:X} addr=0x{address:X} ret_reg=0x{ret_reg:X} sp=0x{sp:X}"
            );
            eprintln!("[NULL_CALL] cx=0x{cx:X} dx=0x{dx:X} r8=0x{r8:X} r9=0x{r9:X}");
            // Dump cx as UNICODE_STRING (cx=arg0 at call site)
            if cx > 0x10000 {
                if let Ok(us_bytes) = engine.core.modules.memory().read(cx, 16) {
                    let length = u16::from_le_bytes([us_bytes[0], us_bytes[1]]);
                    let max_length = u16::from_le_bytes([us_bytes[2], us_bytes[3]]);
                    let buffer = if is_x86 {
                        u32::from_le_bytes([us_bytes[4], us_bytes[5], us_bytes[6], us_bytes[7]])
                            as u64
                    } else {
                        u64::from_le_bytes([
                            us_bytes[8],
                            us_bytes[9],
                            us_bytes[10],
                            us_bytes[11],
                            us_bytes[12],
                            us_bytes[13],
                            us_bytes[14],
                            us_bytes[15],
                        ])
                    };
                    eprintln!("[NULL_CALL] cx as UNICODE_STRING: Length={length} MaxLength={max_length} Buffer=0x{buffer:X}");
                    // Read the string content
                    if buffer > 0x10000 && length > 0 && (length as usize) < 512 {
                        if let Ok(str_bytes) =
                            engine.core.modules.memory().read(buffer, length as usize)
                        {
                            let wide: Vec<u16> = str_bytes
                                .chunks(2)
                                .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                                .collect();
                            let s = String::from_utf16_lossy(&wide);
                            eprintln!("[NULL_CALL] cx UNICODE_STRING value: \"{s}\"");
                        }
                    }
                }
                // Also dump wider memory at cx to see structure
                if let Ok(wide_mem) = engine.core.modules.memory().read(cx, 0x80) {
                    let hex_dump: Vec<String> = wide_mem
                        .chunks(8)
                        .enumerate()
                        .map(|(i, c)| {
                            let v = u64::from_le_bytes(c.try_into().unwrap_or([0; 8]));
                            // Try to decode as UTF-16 if it looks like text
                            let text = if v > 0x20 && v < 0x800000000000u64 {
                                let chars: Vec<u16> = c
                                    .chunks(2)
                                    .map(|b| u16::from_le_bytes([b[0], *b.get(1).unwrap_or(&0)]))
                                    .collect();
                                let s = String::from_utf16_lossy(&chars);
                                if s.chars().all(|c| c.is_ascii_graphic() || c == ' ')
                                    && !s.is_empty()
                                {
                                    format!(" \"{s}\"")
                                } else {
                                    String::new()
                                }
                            } else {
                                String::new()
                            };
                            format!("  +0x{:02X}: 0x{:X}{}", i * 8, v, text)
                        })
                        .collect();
                    eprintln!("[NULL_CALL] memory at cx (0x{cx:X}):");
                    for line in hex_dump {
                        eprintln!("{line}");
                    }
                }
            }
            // Dump r8/dx as UNICODE_STRING too (stack address often used for UNICODE_STRING)
            for (name, addr) in [("r8", r8), ("dx", dx)] {
                if addr > 0x10000 {
                    if let Ok(us_bytes) = engine.core.modules.memory().read(addr, 16) {
                        let length = u16::from_le_bytes([us_bytes[0], us_bytes[1]]);
                        let _max_length = u16::from_le_bytes([us_bytes[2], us_bytes[3]]);
                        let buffer = if is_x86 {
                            u32::from_le_bytes([us_bytes[4], us_bytes[5], us_bytes[6], us_bytes[7]])
                                as u64
                        } else {
                            u64::from_le_bytes([
                                us_bytes[8],
                                us_bytes[9],
                                us_bytes[10],
                                us_bytes[11],
                                us_bytes[12],
                                us_bytes[13],
                                us_bytes[14],
                                us_bytes[15],
                            ])
                        };
                        if length > 0 && buffer > 0x10000 && (length as usize) < 512 {
                            if let Ok(str_bytes) =
                                engine.core.modules.memory().read(buffer, length as usize)
                            {
                                let wide: Vec<u16> = str_bytes
                                    .chunks(2)
                                    .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                                    .collect();
                                let s = String::from_utf16_lossy(&wide);
                                eprintln!("[NULL_CALL] {name} UNICODE_STRING: Length={length} Buffer=0x{buffer:X} value=\"{s}\"");
                            }
                        }
                    }
                }
            }
            // Dump si dispatch table (wider: 0x100 bytes = 32 entries)
            if si > 0x10000 {
                if let Ok(bytes) = engine.core.modules.memory().read(si, 0x100) {
                    let pointer_size: usize = if is_x86 { 4 } else { 8 };
                    let slots: Vec<String> = bytes
                        .chunks(pointer_size)
                        .enumerate()
                        .map(|(i, c)| {
                            let v = if is_x86 {
                                u32::from_le_bytes(c.try_into().unwrap_or([0; 4])) as u64
                            } else {
                                u64::from_le_bytes(c.try_into().unwrap_or([0; 8]))
                            };
                            let hook_info = engine
                                .core
                                .hooks
                                .binding_for_address(v)
                                .map(|(m, f)| format!("→ {}!{}", m, f))
                                .unwrap_or_default();
                            if v != 0 || !hook_info.is_empty() {
                                format!("[si+0x{:X}]=0x{:X}{}", i * pointer_size, v, hook_info)
                            } else {
                                String::new()
                            }
                        })
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !slots.is_empty() {
                        eprintln!("[NULL_CALL] si dispatch table (non-zero):");
                        for s in slots {
                            eprintln!("  {s}");
                        }
                    }
                }
            }

            // For genuine NULL_CALLs (not synthetic-return faults), redirect
            // to the sentinel so the thread terminates cleanly.  This avoids
            // the pending_fault path where the x64-shared-epilogue handler
            // can incorrectly match pc=0 / address=0 and cause an infinite
            // log-and-retry loop.
            if engine.trace.active_x64_synthetic_call.is_none() {
                let _ = unicorn.reg_write(pc_reg, engine.core.native_return_sentinel);
                let _ = unicorn.emu_stop();
                return false;
            }
        }
    }
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
    state.pending_fault = Some(UnicornFault::memory_access(
        access,
        address,
        size as usize,
        pc,
    ));
    let _ = unicorn.emu_stop();
    false
}

/// Renders the `run` summary.
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

/// Reads the first `len` bytes of a named export from a real DLL file on disk.
/// Returns `None` if the DLL or export cannot be found.
fn read_real_prologue(
    module: &str,
    function: &str,
    search_paths: &[std::path::PathBuf],
    len: usize,
) -> Option<Vec<u8>> {
    let dll_path = resolve_real_dll_path(module, search_paths)?;
    let bytes = fs::read(&dll_path).ok()?;
    let pe = PE::parse(&bytes).ok()?;
    let export = pe.exports.iter().find(|e| {
        e.name
            .map(|n| n.eq_ignore_ascii_case(function))
            .unwrap_or(false)
    })?;
    let rva = export.rva as usize;
    if rva == 0 {
        return None;
    }
    let file_offset = rva_to_file_offset(&pe, rva)?;
    if file_offset.saturating_add(len) > bytes.len() {
        return None;
    }
    Some(bytes[file_offset..file_offset + len].to_vec())
}

/// Resolves a module name to a real DLL file path in the search paths.
fn resolve_real_dll_path(
    module: &str,
    search_paths: &[std::path::PathBuf],
) -> Option<std::path::PathBuf> {
    let module_lower = module.to_ascii_lowercase();
    let candidates = if module_lower.ends_with(".dll") {
        vec![module_lower.clone()]
    } else {
        vec![format!("{module_lower}.dll"), module_lower]
    };
    for root in search_paths {
        for root in module_snapshot_search_roots_static(root) {
            for candidate in &candidates {
                let path = root.join(candidate);
                if path.exists() {
                    return Some(path);
                }
                // Case-insensitive fallback
                if let Ok(entries) = fs::read_dir(&root) {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                        if name == *candidate {
                            return Some(entry.path());
                        }
                    }
                }
            }
        }
    }
    None
}

fn module_snapshot_search_roots_static(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let suffixes: &[&str] = &[
        "",
        "System32",
        "SysWOW64",
        "Windows",
        "Windows/System32",
        "Windows/SysWOW64",
        "dlls",
        "dlls/System32",
        "dlls/SysWOW64",
    ];
    let mut roots = Vec::new();
    for suffix in suffixes {
        let candidate = if suffix.is_empty() {
            root.to_path_buf()
        } else {
            root.join(suffix)
        };
        if candidate.is_dir()
            && !roots
                .iter()
                .any(|existing: &std::path::PathBuf| existing == &candidate)
        {
            roots.push(candidate);
        }
    }
    roots
}

fn rva_to_file_offset(pe: &PE, rva: usize) -> Option<usize> {
    for section in &pe.sections {
        let section_start = section.virtual_address as usize;
        let section_size = std::cmp::max(section.virtual_size, section.size_of_raw_data) as usize;
        let section_end = section_start.checked_add(section_size)?;
        if (section_start..section_end).contains(&rva) {
            let offset_in_section = rva.checked_sub(section_start)?;
            let raw_offset = section.pointer_to_raw_data as usize;
            return raw_offset.checked_add(offset_in_section);
        }
    }
    let header_size = pe
        .header
        .optional_header
        .as_ref()
        .map(|header| header.windows_fields.size_of_headers as usize)
        .unwrap_or_default();
    (rva < header_size).then_some(rva)
}
