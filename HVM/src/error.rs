use std::path::PathBuf;

use thiserror::Error;

/// Captures configuration loading failures for the Rust compatibility layer.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadConfig {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    ParseConfig {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to resolve path {path}: {source}")]
    ResolvePath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid config field `{field}`: {detail}")]
    InvalidField { field: &'static str, detail: String },
    #[error("config field `main_module` is required")]
    MissingMainModule,
}

/// Captures top-level runtime and CLI failures while the Rust engine is being ported.
#[derive(Debug, Error)]
pub enum VmError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Memory(#[from] MemoryError),
    #[error("failed to read environment profile {path}: {source}")]
    ReadEnvironmentProfile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse environment profile {path}: {source}")]
    ParseEnvironmentProfile {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid environment profile: {detail}")]
    EnvironmentProfileData { detail: String },
    #[error("failed to read file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse PE {path}: {source}")]
    ParsePe {
        path: PathBuf,
        #[source]
        source: goblin::error::Error,
    },
    #[error("unsupported PE execution architecture during {operation}: {path} ({arch})")]
    UnsupportedExecutionArchitecture {
        operation: &'static str,
        path: PathBuf,
        arch: String,
    },
    #[error("unsupported PE machine type: 0x{0:04X}")]
    UnsupportedMachine(u16),
    #[error("PE file is missing an optional header: {0}")]
    MissingOptionalHeader(PathBuf),
    #[error("module not found: {0}")]
    ModuleNotFound(String),
    #[error("runtime invariant violated: {0}")]
    RuntimeInvariant(&'static str),
    #[error("failed to run command `{program}`: {source}")]
    CommandIo {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("command `{program}` failed with code {code:?}: {stderr}")]
    CommandFailed {
        program: String,
        code: Option<i32>,
        stderr: String,
    },
    #[error("failed to parse {kind} output: {output}")]
    OutputParse { kind: &'static str, output: String },
    #[error("failed to write output {path}: {source}")]
    OutputIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("native execution failed during {op}: {detail}")]
    NativeExecution { op: &'static str, detail: String },
}

/// Captures memory-manager failures, including live Unicorn backend errors.
#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("requested region overlaps an existing mapping at 0x{base:X} size 0x{size:X}")]
    OverlappingRegion { base: u64, size: u64 },
    #[error("no mapped region contains address 0x{address:X} size 0x{size:X}")]
    MissingRegion { address: u64, size: u64 },
    #[error("unable to reserve 0x{size:X} bytes")]
    OutOfMemory { size: u64 },
    #[error("native memory backend failed during {op}: {detail}")]
    NativeBackend { op: &'static str, detail: String },
}
