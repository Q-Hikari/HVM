use crate::hooks::families::core::kernel32::Kernel32Api;
use crate::hooks::families::core::ntdll::NtdllApi;
use crate::hooks::families::shell_services::shell32::Shell32Api;
use crate::hooks::registry::HookRegistry;
use crate::hooks::{register_all_family_hooks, representative_hook_exports};
use crate::managers::process_manager::ProcessManager;
use crate::runtime::scheduler::ThreadScheduler;

/// Summarizes how many representative exports were recognized or left unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookBindReport {
    pub bound: usize,
    pub unsupported_seen: usize,
}

/// Provides a loaded Rust runtime slice that integration tests can drive directly.
#[derive(Debug)]
pub struct LoadedTestEngine {
    registry: HookRegistry,
    scheduler: ThreadScheduler,
    processes: ProcessManager,
    last_error: u32,
    command_line: String,
    main_thread_tid: u32,
    main_thread_handle: u32,
}

impl LoadedTestEngine {
    /// Returns the registered synthetic export definitions available to the test runtime.
    pub fn registry(&self) -> &HookRegistry {
        &self.registry
    }

    /// Returns the scheduler state used by the test runtime.
    pub fn scheduler(&self) -> &ThreadScheduler {
        &self.scheduler
    }

    /// Returns a test helper for driving the `kernel32.dll` hook surface.
    pub fn kernel32(&mut self) -> Kernel32Api<'_> {
        Kernel32Api::new(self)
    }

    /// Returns a test helper for driving the `ntdll.dll` hook surface.
    pub fn ntdll(&mut self) -> NtdllApi<'_> {
        NtdllApi::new(self)
    }

    /// Returns a test helper for driving the `shell32.dll` hook surface.
    pub fn shell32(&mut self) -> Shell32Api<'_> {
        Shell32Api::new(self)
    }

    /// Returns the process manager state used by the test runtime.
    pub fn processes(&self) -> &ProcessManager {
        &self.processes
    }

    /// Returns the main thread handle registered during test-engine load.
    pub fn main_thread_handle(&self) -> u32 {
        self.main_thread_handle
    }

    /// Polls blocked scheduler state using the provided synthetic tick value.
    pub fn poll_scheduler(&mut self, tick: u64) -> Vec<u32> {
        self.scheduler.poll_blocked_threads(tick)
    }

    /// Binds representative exports across the generated stub DLL families for registry tests.
    pub fn bind_representative_hook_exports_for_test(&mut self) -> HookBindReport {
        let mut bound = 0usize;
        for (module, function) in representative_hook_exports() {
            let supported = self.registry.definition(module, function).is_some();
            let _ = self.registry.bind_stub(module, function);
            if supported {
                bound += 1;
            }
        }

        let unsupported_probes = [
            ("advapi32.dll", "DefinitelyMissingExport"),
            ("imaginary.dll", "TotallyMissingExport"),
        ];
        let mut unsupported_seen = 0usize;
        for (module, function) in unsupported_probes {
            let supported = self.registry.definition(module, function).is_some();
            let _ = self.registry.bind_stub(module, function);
            if !supported {
                unsupported_seen += 1;
            }
        }

        HookBindReport {
            bound,
            unsupported_seen,
        }
    }

    /// Returns the last-error code currently stored by the test runtime.
    pub(crate) fn last_error(&self) -> u32 {
        self.last_error
    }

    /// Updates the last-error code currently stored by the test runtime.
    pub(crate) fn set_last_error(&mut self, value: u32) {
        self.last_error = value;
    }

    /// Returns the command line mirrored by the test runtime.
    pub(crate) fn command_line(&self) -> &str {
        &self.command_line
    }

    /// Returns the main thread identifier registered during test-engine load.
    pub(crate) fn main_thread_tid(&self) -> u32 {
        self.main_thread_tid
    }

    /// Returns mutable process-manager access for hook helpers.
    pub(crate) fn processes_mut(&mut self) -> &mut ProcessManager {
        &mut self.processes
    }

    /// Returns mutable scheduler access for hook helpers.
    pub(crate) fn scheduler_mut(&mut self) -> &mut ThreadScheduler {
        &mut self.scheduler
    }
}

/// Builds a loaded test engine with a registered main thread and hook definitions.
pub fn build_loaded_engine() -> LoadedTestEngine {
    let mut registry = HookRegistry::for_tests();
    register_all_family_hooks(&mut registry);

    let mut scheduler = ThreadScheduler::for_tests();
    let main_thread = scheduler.register_main_thread(0x401000).unwrap();

    LoadedTestEngine {
        registry,
        scheduler,
        processes: ProcessManager::for_tests(),
        last_error: 0,
        command_line: "Sample/getmidm2.exe".to_string(),
        main_thread_tid: main_thread.tid,
        main_thread_handle: main_thread.handle,
    }
}
