/// Captures a single DLL import line in `inspect` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDescriptorReport {
    pub dll: String,
    pub symbols: Vec<String>,
}

/// Describes one loaded PE image or synthetic DLL region in the emulated runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardedExportTarget {
    ByName { module: String, function: String },
    ByOrdinal { module: String, ordinal: u16 },
}

/// Describes one loaded PE image or synthetic DLL region in the emulated runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRecord {
    pub name: String,
    pub path: Option<std::path::PathBuf>,
    pub arch: String,
    pub is_dll: bool,
    pub base: u64,
    pub size: u64,
    pub entrypoint: u64,
    pub image_base: u64,
    pub synthetic: bool,
    pub tls_callbacks: Vec<u64>,
    pub initialized: bool,
    pub exports_by_name: std::collections::BTreeMap<String, u64>,
    pub export_name_text_by_key: std::collections::BTreeMap<String, String>,
    pub exports_by_ordinal: std::collections::BTreeMap<u16, u64>,
    pub forwarded_exports_by_name: std::collections::BTreeMap<String, ForwardedExportTarget>,
    pub forwarded_exports_by_ordinal: std::collections::BTreeMap<u16, ForwardedExportTarget>,
    pub stub_cursor: u64,
}

/// Captures the PE metadata printed by the Python `inspect` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeInspectReport {
    pub name: String,
    pub arch: String,
    pub image_base: u64,
    pub entrypoint_rva: u64,
    pub size_of_image: u32,
    pub imports: Vec<ImportDescriptorReport>,
    pub has_tls: bool,
    pub has_reloc: bool,
}

/// Captures the top-level execution summary returned by the Rust `run` flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStopReason {
    ProcessExit,
    MainThreadTerminated,
    AllThreadsTerminated,
    InstructionBudgetExhausted,
    SchedulerIdle,
    RunComplete,
}

impl RunStopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessExit => "process_exit",
            Self::MainThreadTerminated => "main_thread_terminated",
            Self::AllThreadsTerminated => "all_threads_terminated",
            Self::InstructionBudgetExhausted => "instruction_budget_exhausted",
            Self::SchedulerIdle => "scheduler_idle",
            Self::RunComplete => "run_complete",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunResult {
    pub entrypoint: u64,
    pub instructions: u64,
    pub stopped: bool,
    pub exit_code: Option<u32>,
    pub stop_reason: RunStopReason,
}
