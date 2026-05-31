use std::collections::BTreeSet;
use std::fs;
use std::path::{absolute, Path, PathBuf};

use serde_json::Value;

pub use crate::environment_profile::EnvironmentOverrides;
use crate::error::ConfigError;

/// Engine configuration loaded from JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    pub main_module: PathBuf,
    pub process_image: Option<PathBuf>,
    pub parent_process_image: Option<PathBuf>,
    pub parent_process_pid: Option<u32>,
    pub parent_process_command_line: Option<String>,
    pub entry_module: Option<PathBuf>,
    pub entry_export: Option<String>,
    pub entry_ordinal: Option<u16>,
    pub entry_args: Vec<EntryArgument>,
    pub module_search_paths: Vec<PathBuf>,
    pub modules_always_exist: bool,
    pub functions_always_exist: bool,
    pub module_directory_x86: Option<PathBuf>,
    pub module_directory_x64: Option<PathBuf>,
    pub whitelist_modules: BTreeSet<String>,
    pub preload_modules: Vec<String>,
    pub prologue_source_paths: Vec<PathBuf>,
    pub volumes: Vec<VolumeMount>,
    pub auto_mount_module_dirs: bool,
    pub allowed_read_dirs: Vec<PathBuf>,
    pub blocked_read_dirs: Vec<PathBuf>,
    pub hidden_device_paths: Vec<String>,
    pub hidden_registry_keys: Vec<String>,
    pub http_response_rules: Vec<HttpResponseRule>,
    pub sandbox_output_dir: PathBuf,
    pub trace_api_calls: bool,
    pub trace_native_events: bool,
    pub api_log_path: Option<PathBuf>,
    pub api_jsonl_path: Option<PathBuf>,
    pub api_human_log_path: Option<PathBuf>,
    pub api_log_to_console: bool,
    pub api_log_include_return: bool,
    pub api_log_include_context: bool,
    pub api_log_stack_words: usize,
    pub api_log_string_limit: usize,
    pub console_output_to_console: bool,
    pub console_output_path: Option<PathBuf>,
    pub unknown_api_policy: String,
    pub stack_reserve_size: Option<u64>,
    pub max_instructions: u64,
    pub command_line: String,
    pub environment_profile: Option<PathBuf>,
    pub environment_overrides: Option<EnvironmentOverrides>,
    pub interception_rules: InterceptionRules,
    pub observation_checkpoints: Vec<u64>,
    pub exit_on_unsupported_hook: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeMount {
    pub host_path: PathBuf,
    pub guest_path: String,
    pub recursive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponseRule {
    pub host: Option<String>,
    pub path: Option<String>,
    pub verb: Option<String>,
    pub responses: Vec<HttpResponsePayload>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponsePayload {
    pub status_code: u32,
    pub headers: Vec<HttpResponseHeader>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponseHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryArgument {
    Value(u64),
    Null,
    AnsiString(String),
    WideString(String),
    Bytes(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Interception rules — fine-grained control over emulated environment responses
// ---------------------------------------------------------------------------

/// Top-level container for all interception rule categories.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InterceptionRules {
    pub registry: Vec<RegistryInterceptionRule>,
    pub files: Vec<FileInterceptionRule>,
    pub system: Vec<SystemInterceptionRule>,
    pub devices: Vec<DeviceInterceptionRule>,
}

/// Action to take when an interception rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptionAction {
    /// Pretend the resource does not exist.
    NotFound,
    /// Return `ERROR_ACCESS_DENIED`.
    AccessDenied,
    /// Return a specific Win32 error code.
    ErrorCode(u32),
    /// Return crafted data instead of the real emulated value.
    ReturnData(InterceptionValue),
}

/// A single data value used by `InterceptionAction::ReturnData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptionValue {
    String(String),
    Dword(u32),
    Qword(u64),
    Bytes(Vec<u8>),
}

/// Interception rule for registry key/value access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryInterceptionRule {
    /// Normalized registry path (e.g. `HKLM\Software\Microsoft\Windows`).
    /// Supports trailing `*` as a wildcard prefix match.
    pub path: String,
    /// If `Some`, only matches queries for this specific value name.
    /// If `None`, matches any open/query on the key path.
    pub value_name: Option<String>,
    /// The action to take when this rule matches.
    pub action: InterceptionAction,
}

/// Interception rule for file/device access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInterceptionRule {
    /// Normalized guest file path (e.g. `C:\Windows\System32\drivers\etc\hosts`).
    /// Supports trailing `*` as a wildcard prefix match.
    pub path: String,
    /// The action to take when this rule matches.
    pub action: FileInterceptionAction,
}

/// Action to take when a file interception rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileInterceptionAction {
    /// Pretend the file does not exist.
    NotFound,
    /// Return `ERROR_ACCESS_DENIED`.
    AccessDenied,
    /// Serve the given bytes as file content.
    ReturnContent { data: Vec<u8> },
    /// Redirect to a file on the host filesystem.
    Redirect { host_path: PathBuf },
}

/// Interception rule for system information queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInterceptionRule {
    /// Query identifier in `ApiName.field` format
    /// (e.g. `GetSystemInfo.numberOfProcessors`).
    pub query: String,
    /// The value to return when this rule matches.
    pub value: u64,
}

/// Interception rule for device IOCTL responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInterceptionRule {
    /// Normalized device path (e.g. `\\.\360SelfProtection`).
    pub path: String,
    /// IOCTL control code to match, or `None` to match any code.
    pub ioctl_code: Option<u64>,
    /// Raw bytes to write to the output buffer.
    pub output: Vec<u8>,
    /// Value to write to `lpBytesReturned` (0 to leave unchanged).
    pub bytes_returned: u32,
}

impl EngineConfig {
    /// Returns whether the given module name is explicitly whitelisted.
    pub fn is_whitelisted(&self, module_name: &str) -> bool {
        let lower = module_name.to_ascii_lowercase();
        self.whitelist_modules
            .iter()
            .any(|entry| entry.to_ascii_lowercase() == lower)
    }

    /// Returns whether missing modules should fall back to synthetic decoys.
    pub fn modules_always_exist(&self) -> bool {
        self.modules_always_exist
    }

    /// Returns whether missing exports should bind permissive synthetic stubs.
    pub fn functions_always_exist(&self) -> bool {
        self.functions_always_exist
    }

    /// Returns the optional decoy directory configured for one runtime architecture.
    pub fn module_directory_for_arch(&self, arch_name: &str) -> Option<&Path> {
        if arch_name.eq_ignore_ascii_case("x64") || arch_name.eq_ignore_ascii_case("amd64") {
            self.module_directory_x64.as_deref()
        } else if arch_name.eq_ignore_ascii_case("x86")
            || arch_name.eq_ignore_ascii_case("i386")
            || arch_name.eq_ignore_ascii_case("i686")
        {
            self.module_directory_x86.as_deref()
        } else {
            None
        }
    }

    /// Returns the ordered real-module search roots for one runtime architecture.
    pub fn module_resolution_paths_for_arch(&self, arch_name: &str) -> Vec<PathBuf> {
        let mut paths = self.module_search_paths.clone();
        if let Some(decoy_dir) = self.module_directory_for_arch(arch_name) {
            let decoy_dir = decoy_dir.to_path_buf();
            if !paths.iter().any(|existing| existing == &decoy_dir) {
                paths.push(decoy_dir);
            }
        }
        paths
    }

    /// Returns the process image path exposed through PEB/GetModuleHandle(NULL)-style queries.
    pub fn process_image_path(&self) -> &Path {
        self.process_image
            .as_deref()
            .unwrap_or(self.main_module.as_path())
    }

    /// Returns the module that provides the effective execution entrypoint/export.
    pub fn entry_module_path(&self) -> &Path {
        self.entry_module
            .as_deref()
            .unwrap_or(self.main_module.as_path())
    }

    /// Returns whether the config explicitly targets one DLL export.
    pub fn uses_export_entry(&self) -> bool {
        self.entry_export.is_some() || self.entry_ordinal.is_some()
    }

    /// Returns the configured device-path concealment rule that matches one requested path.
    pub fn hidden_device_rule_for(&self, path: &str) -> Option<&str> {
        let normalized_path = normalize_artifact_token(path);
        self.hidden_device_paths
            .iter()
            .find(|candidate| {
                let normalized_rule = normalize_artifact_token(candidate);
                !normalized_rule.is_empty() && normalized_rule == normalized_path
            })
            .map(String::as_str)
    }

    /// Returns the configured registry-key concealment rule that matches one requested key path.
    pub fn hidden_registry_rule_for(&self, full_path: &str, subkey: &str) -> Option<&str> {
        let normalized_full = normalize_artifact_token(full_path);
        let normalized_subkey = normalize_artifact_token(subkey);
        let normalized_without_root = normalized_full
            .split_once('\\')
            .map(|(_, remainder)| remainder)
            .unwrap_or(normalized_full.as_str());
        self.hidden_registry_keys
            .iter()
            .find(|candidate| {
                let normalized_rule = normalize_artifact_token(candidate);
                !normalized_rule.is_empty()
                    && (path_matches_rule(&normalized_full, &normalized_rule)
                        || path_matches_rule(normalized_without_root, &normalized_rule)
                        || path_matches_rule(&normalized_subkey, &normalized_rule))
            })
            .map(String::as_str)
    }

    /// Returns the configured HTTP response rule that matches one emulated request.
    pub fn http_response_rule_for(
        &self,
        host: &str,
        path: &str,
        verb: &str,
    ) -> Option<&HttpResponseRule> {
        self.http_response_rule_with_index_for(host, path, verb)
            .map(|(_, rule)| rule)
    }

    /// Returns the first registry interception rule matching the given path and optional value name.
    /// Paths are matched case-insensitively; a trailing `*` in the rule acts as a prefix wildcard.
    pub fn interception_rule_for_registry(
        &self,
        full_path: &str,
        value_name: Option<&str>,
    ) -> Option<&RegistryInterceptionRule> {
        let normalized_query = normalize_registry_interception_path(full_path);
        self.interception_rules.registry.iter().find(|rule| {
            let path_matches = if rule.path.ends_with('*') {
                let prefix = &rule.path[..rule.path.len() - 1];
                normalized_query == prefix.trim_end_matches('\\')
                    || normalized_query.starts_with(prefix)
            } else {
                normalized_query == rule.path
            };
            if !path_matches {
                return false;
            }
            match (&rule.value_name, value_name) {
                (None, _) => true,
                (Some(rule_name), Some(query_name)) => rule_name.eq_ignore_ascii_case(query_name),
                (Some(_), None) => false,
            }
        })
    }

    /// Returns the first device interception rule matching the given path and IOCTL code.
    pub fn interception_rule_for_device(
        &self,
        device_path: &str,
        ioctl_code: u64,
    ) -> Option<&DeviceInterceptionRule> {
        let normalized = normalize_file_interception_path(device_path);
        self.interception_rules.devices.iter().find(|rule| {
            let path_match = if rule.path.ends_with('*') {
                let prefix = &rule.path[..rule.path.len() - 1];
                normalized == prefix.trim_end_matches('\\') || normalized.starts_with(prefix)
            } else {
                normalized == rule.path
            };
            let code_match = rule.ioctl_code.map(|c| c == ioctl_code).unwrap_or(true);
            path_match && code_match
        })
    }

    /// Returns the first file interception rule matching the given guest path.
    /// Paths are matched case-insensitively; a trailing `*` acts as a prefix wildcard.
    pub fn interception_rule_for_file(&self, guest_path: &str) -> Option<&FileInterceptionRule> {
        let normalized_query = normalize_file_interception_path(guest_path);
        self.interception_rules.files.iter().find(|rule| {
            if rule.path.ends_with('*') {
                let prefix = &rule.path[..rule.path.len() - 1];
                normalized_query == prefix.trim_end_matches('\\')
                    || normalized_query.starts_with(prefix)
            } else {
                normalized_query == rule.path
            }
        })
    }

    /// Returns the first system interception rule matching the given query identifier.
    pub fn interception_rule_for_system(&self, query: &str) -> Option<&SystemInterceptionRule> {
        let normalized = query.to_ascii_lowercase();
        self.interception_rules
            .system
            .iter()
            .find(|rule| rule.query.eq_ignore_ascii_case(&normalized))
    }

    /// Returns the index and HTTP response rule that matches one emulated request.
    pub fn http_response_rule_with_index_for(
        &self,
        host: &str,
        path: &str,
        verb: &str,
    ) -> Option<(usize, &HttpResponseRule)> {
        let normalized_host = normalize_http_host(host);
        let normalized_path = normalize_http_path(path);
        let normalized_verb = normalize_http_verb(verb);
        self.http_response_rules
            .iter()
            .enumerate()
            .find(|(_, rule)| {
                let host_matches = rule.host.as_deref().is_none_or(|candidate| {
                    http_token_matches(&normalized_host, &normalize_http_host(candidate))
                });
                let path_matches = rule.path.as_deref().is_none_or(|candidate| {
                    http_token_matches(&normalized_path, &normalize_http_path(candidate))
                });
                let verb_matches = rule.verb.as_deref().is_none_or(|candidate| {
                    http_token_matches(&normalized_verb, &normalize_http_verb(candidate))
                });
                host_matches && path_matches && verb_matches
            })
    }

    /// Builds a minimal config for Rust-only manager tests.
    pub fn for_tests(sandbox_output_dir: PathBuf) -> Self {
        Self {
            main_module: PathBuf::new(),
            process_image: None,
            parent_process_image: None,
            parent_process_pid: None,
            parent_process_command_line: None,
            entry_module: None,
            entry_export: None,
            entry_ordinal: None,
            entry_args: Vec::new(),
            module_search_paths: Vec::new(),
            modules_always_exist: true,
            functions_always_exist: true,
            module_directory_x86: None,
            module_directory_x64: None,
            whitelist_modules: BTreeSet::new(),
            preload_modules: Vec::new(),
            prologue_source_paths: Vec::new(),
            volumes: Vec::new(),
            auto_mount_module_dirs: true,
            allowed_read_dirs: Vec::new(),
            blocked_read_dirs: Vec::new(),
            hidden_device_paths: Vec::new(),
            hidden_registry_keys: Vec::new(),
            http_response_rules: Vec::new(),
            sandbox_output_dir,
            trace_api_calls: false,
            trace_native_events: false,
            api_log_path: None,
            api_jsonl_path: None,
            api_human_log_path: None,
            api_log_to_console: false,
            api_log_include_return: true,
            api_log_include_context: false,
            api_log_stack_words: 4,
            api_log_string_limit: 160,
            console_output_to_console: false,
            console_output_path: None,
            unknown_api_policy: "log_zero".to_string(),
            stack_reserve_size: None,
            max_instructions: 1_000_000,
            command_line: String::new(),
            environment_profile: None,
            environment_overrides: None,
            interception_rules: InterceptionRules::default(),
            observation_checkpoints: Vec::new(),
            exit_on_unsupported_hook: false,
        }
    }
}

mod config_parse;

pub use config_parse::load_config;
use config_parse::{
    http_token_matches, normalize_artifact_token, normalize_file_interception_path,
    normalize_http_host, normalize_http_path, normalize_http_verb,
    normalize_registry_interception_path, path_matches_rule,
};
