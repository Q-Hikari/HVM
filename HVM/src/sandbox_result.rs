use serde::Serialize;

/// Top-level structured result returned by the sandbox `analyze` command.
///
/// Serialized to JSON for consumption by external orchestrators (e.g. Go web backend).
#[derive(Debug, Clone, Serialize)]
pub struct SandboxResult {
    // ── metadata ──
    pub sample_hash: String,
    pub sample_size: u64,
    pub arch: String,
    pub timestamp: String,
    pub execution_time_ms: u64,
    pub hvm_version: String,

    // ── execution status ──
    pub status: String,
    pub exit_code: Option<u32>,
    pub stop_reason: String,
    pub instruction_count: u64,
    pub error_message: Option<String>,

    // ── behavior analysis ──
    pub api_calls: Vec<ApiCallRecord>,
    pub network_events: Vec<NetworkEvent>,
    pub file_operations: Vec<FileOperation>,
    pub registry_operations: Vec<RegistryOp>,
    pub process_operations: Vec<ProcessOp>,
    pub dropped_files: Vec<DroppedFile>,
    pub console_output: String,

    // ── PE metadata ──
    pub pe_info: Option<PeInfo>,
}

/// One observed API call with arguments and return value.
#[derive(Debug, Clone, Serialize)]
pub struct ApiCallRecord {
    pub call_id: u64,
    pub tick_ms: u64,
    pub instruction: u64,
    pub tid: u32,
    pub module: String,
    pub function: String,
    pub args: Vec<ApiArg>,
    pub return_value: Option<u64>,
    pub last_error: Option<u32>,
}

/// A single argument captured for an API call.
#[derive(Debug, Clone, Serialize)]
pub struct ApiArg {
    pub index: usize,
    pub name: String,
    pub value: u64,
    pub text: String,
}

/// A network-related event observed during execution.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkEvent {
    pub tick_ms: u64,
    pub kind: String,
    pub protocol: Option<String>,
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
    pub data_size: Option<u64>,
    pub url: Option<String>,
    pub verb: Option<String>,
}

/// A file-system operation observed during execution.
#[derive(Debug, Clone, Serialize)]
pub struct FileOperation {
    pub tick_ms: u64,
    pub kind: String,
    pub path: String,
    pub result: Option<String>,
}

/// A registry operation observed during execution.
#[derive(Debug, Clone, Serialize)]
pub struct RegistryOp {
    pub tick_ms: u64,
    pub kind: String,
    pub path: String,
    pub value_name: Option<String>,
    pub result: Option<String>,
}

/// A process-related operation observed during execution.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessOp {
    pub tick_ms: u64,
    pub kind: String,
    pub image: Option<String>,
    pub command_line: Option<String>,
    pub pid: Option<u32>,
}

/// A file written/dropped by the sample during execution.
#[derive(Debug, Clone, Serialize)]
pub struct DroppedFile {
    pub path: String,
    pub size: u64,
    pub hash: Option<String>,
}

/// PE metadata extracted from the sample before execution.
#[derive(Debug, Clone, Serialize)]
pub struct PeInfo {
    pub arch: String,
    pub image_base: u64,
    pub entrypoint_rva: u64,
    pub size_of_image: u32,
    pub imports: Vec<ImportEntry>,
    pub has_tls: bool,
    pub has_relocations: bool,
}

/// One DLL import entry.
#[derive(Debug, Clone, Serialize)]
pub struct ImportEntry {
    pub dll: String,
    pub symbols: Vec<String>,
}

/// Runtime status values for the sandbox result.
pub mod status {
    pub const COMPLETED: &str = "completed";
    pub const TIMEOUT: &str = "timeout";
    pub const ERROR: &str = "error";
    pub const CRASH: &str = "crash";
}

/// In-memory collector for behavior events during execution.
/// Pushed to from hook handlers, drained by `run_with_result()`.
#[derive(Debug, Clone, Default)]
pub struct BehaviorCollector {
    /// When false (default), all `record_*` calls are no-ops.
    /// Set to true only when `run_with_result()` is called.
    pub enabled: bool,
    pub network_events: Vec<NetworkEvent>,
    pub file_operations: Vec<FileOperation>,
    pub registry_operations: Vec<RegistryOp>,
    pub process_operations: Vec<ProcessOp>,
    pub dropped_files: Vec<DroppedFile>,
    pub console_output: String,
}
