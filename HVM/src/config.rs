use std::collections::BTreeSet;
use std::fs;
use std::path::{absolute, Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

pub use crate::environment_profile::EnvironmentOverrides;
use crate::error::ConfigError;

/// Mirrors the Python runtime configuration shape so existing JSON files remain valid.
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
    pub api_log_string_limit: usize,
    pub console_output_to_console: bool,
    pub console_output_path: Option<PathBuf>,
    pub unknown_api_policy: String,
    pub max_instructions: u64,
    pub command_line: String,
    pub environment_profile: Option<PathBuf>,
    pub environment_overrides: Option<EnvironmentOverrides>,
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

impl EngineConfig {
    /// Returns whether the given module name is explicitly whitelisted.
    pub fn is_whitelisted(&self, module_name: &str) -> bool {
        self.whitelist_modules
            .contains(&module_name.to_ascii_lowercase())
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
            api_log_string_limit: 160,
            console_output_to_console: false,
            console_output_path: None,
            unknown_api_policy: "log_zero".to_string(),
            max_instructions: 1_000_000,
            command_line: String::new(),
            environment_profile: None,
            environment_overrides: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    main_module: Option<String>,
    process_image: Option<String>,
    parent_process_image: Option<String>,
    parent_process_pid: Option<u32>,
    parent_process_command_line: Option<String>,
    entry_module: Option<String>,
    entry_export: Option<String>,
    entry_ordinal: Option<u16>,
    entry_args: Option<Vec<Value>>,
    module_search_paths: Option<Vec<String>>,
    modules_always_exist: Option<bool>,
    functions_always_exist: Option<bool>,
    module_directory_x86: Option<String>,
    module_directory_x64: Option<String>,
    modules: Option<RawModuleSettings>,
    whitelist_modules: Option<Vec<String>>,
    preload_modules: Option<Vec<String>>,
    volumes: Option<Vec<RawVolumeMount>>,
    auto_mount_module_dirs: Option<bool>,
    allowed_read_dirs: Option<Vec<String>>,
    blocked_read_dirs: Option<Vec<String>>,
    hidden_device_paths: Option<Vec<String>>,
    hidden_registry_keys: Option<Vec<String>>,
    http_response_rules: Option<Vec<RawHttpResponseRule>>,
    sandbox_output_dir: Option<String>,
    trace_api_calls: Option<bool>,
    trace_native_events: Option<bool>,
    api_log_path: Option<String>,
    api_jsonl_path: Option<String>,
    api_human_log_path: Option<String>,
    api_log_to_console: Option<bool>,
    api_log_include_return: Option<bool>,
    api_log_string_limit: Option<usize>,
    console_output_to_console: Option<bool>,
    console_output_path: Option<String>,
    unknown_api_policy: Option<String>,
    max_instructions: Option<u64>,
    process_command_line: Option<String>,
    command_line: Option<String>,
    environment_profile: Option<String>,
    environment_overrides: Option<EnvironmentOverrides>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct RawModuleSettings {
    modules_always_exist: Option<bool>,
    functions_always_exist: Option<bool>,
    module_directory_x86: Option<String>,
    module_directory_x64: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct RawHttpResponseRule {
    host: Option<String>,
    path: Option<String>,
    verb: Option<String>,
    responses: Option<Vec<RawHttpResponsePayload>>,
    status_code: Option<u32>,
    headers: Option<Vec<RawHttpResponseHeader>>,
    body: Option<String>,
    body_hex: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct RawHttpResponsePayload {
    status_code: Option<u32>,
    headers: Option<Vec<RawHttpResponseHeader>>,
    body: Option<String>,
    body_hex: Option<String>,
}

impl Default for RawHttpResponseRule {
    fn default() -> Self {
        Self {
            host: None,
            path: None,
            verb: None,
            responses: None,
            status_code: None,
            headers: None,
            body: None,
            body_hex: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RawHttpResponseHeader {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawVolumeMount {
    Compact(String),
    Detailed {
        host_path: String,
        guest_path: String,
        recursive: Option<bool>,
    },
}

/// Loads JSON config files with the same defaults and path resolution rules as the Python baseline.
pub fn load_config(path: impl AsRef<Path>) -> Result<EngineConfig, ConfigError> {
    let requested_path = path.as_ref().to_path_buf();
    let config_path = absolute(&requested_path).map_err(|source| ConfigError::ResolvePath {
        path: requested_path.clone(),
        source,
    })?;
    let raw_text = fs::read_to_string(&config_path).map_err(|source| ConfigError::ReadConfig {
        path: config_path.clone(),
        source,
    })?;
    let raw: RawConfig =
        serde_json::from_str(&raw_text).map_err(|source| ConfigError::ParseConfig {
            path: config_path.clone(),
            source,
        })?;
    let base_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let project_base = base_dir.parent().unwrap_or(base_dir.as_path());
    let main_module_raw = raw.main_module.ok_or(ConfigError::MissingMainModule)?;
    let main_module = resolve_path_like_python(project_base, Path::new(&main_module_raw))?;
    if raw.entry_export.is_some() && raw.entry_ordinal.is_some() {
        return Err(ConfigError::InvalidField {
            field: "entry_export",
            detail: "entry_export and entry_ordinal are mutually exclusive".to_string(),
        });
    }

    let trace_api_calls = raw.trace_api_calls.unwrap_or(false);
    let trace_native_events = raw.trace_native_events.unwrap_or(false);
    let module_settings = raw.modules.clone().unwrap_or_default();
    let process_command_line = raw
        .process_command_line
        .filter(|value| !value.trim().is_empty());

    Ok(EngineConfig {
        main_module,
        process_image: to_optional_path(raw.process_image.as_deref(), project_base)?,
        parent_process_image: to_optional_path(raw.parent_process_image.as_deref(), project_base)?,
        parent_process_pid: raw.parent_process_pid,
        parent_process_command_line: raw
            .parent_process_command_line
            .filter(|value| !value.trim().is_empty()),
        entry_module: to_optional_path(raw.entry_module.as_deref(), project_base)?,
        entry_export: raw.entry_export.filter(|value| !value.trim().is_empty()),
        entry_ordinal: raw.entry_ordinal,
        entry_args: parse_entry_args(raw.entry_args)?,
        module_search_paths: to_path_list(raw.module_search_paths.as_deref(), project_base)?,
        modules_always_exist: raw
            .modules_always_exist
            .or(module_settings.modules_always_exist)
            .unwrap_or(true),
        functions_always_exist: raw
            .functions_always_exist
            .or(module_settings.functions_always_exist)
            .unwrap_or(true),
        module_directory_x86: to_optional_path(
            raw.module_directory_x86
                .as_deref()
                .or(module_settings.module_directory_x86.as_deref()),
            project_base,
        )?,
        module_directory_x64: to_optional_path(
            raw.module_directory_x64
                .as_deref()
                .or(module_settings.module_directory_x64.as_deref()),
            project_base,
        )?,
        whitelist_modules: raw
            .whitelist_modules
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.to_ascii_lowercase())
            .collect(),
        preload_modules: raw.preload_modules.unwrap_or_default(),
        volumes: parse_volume_mounts(raw.volumes, project_base)?,
        auto_mount_module_dirs: raw.auto_mount_module_dirs.unwrap_or(true),
        allowed_read_dirs: to_path_list(raw.allowed_read_dirs.as_deref(), project_base)?,
        blocked_read_dirs: to_path_list(raw.blocked_read_dirs.as_deref(), project_base)?,
        hidden_device_paths: raw.hidden_device_paths.unwrap_or_default(),
        hidden_registry_keys: raw.hidden_registry_keys.unwrap_or_default(),
        http_response_rules: parse_http_response_rules(raw.http_response_rules)?,
        sandbox_output_dir: resolve_path_like_python(
            project_base,
            Path::new(
                raw.sandbox_output_dir
                    .as_deref()
                    .unwrap_or(".hvm_hikari_virtual_engine/output"),
            ),
        )?,
        trace_api_calls,
        trace_native_events,
        api_log_path: to_optional_path(raw.api_log_path.as_deref(), project_base)?,
        api_jsonl_path: to_optional_path(raw.api_jsonl_path.as_deref(), project_base)?,
        api_human_log_path: to_optional_path(raw.api_human_log_path.as_deref(), project_base)?,
        api_log_to_console: raw.api_log_to_console.unwrap_or(false),
        api_log_include_return: raw.api_log_include_return.unwrap_or(true),
        api_log_string_limit: raw.api_log_string_limit.unwrap_or(160),
        console_output_to_console: raw.console_output_to_console.unwrap_or(false),
        console_output_path: to_optional_path(raw.console_output_path.as_deref(), project_base)?,
        unknown_api_policy: raw
            .unknown_api_policy
            .unwrap_or_else(|| "log_zero".to_string()),
        max_instructions: raw.max_instructions.unwrap_or(1_000_000),
        command_line: process_command_line.unwrap_or_else(|| raw.command_line.unwrap_or_default()),
        environment_profile: to_optional_path(raw.environment_profile.as_deref(), project_base)?,
        environment_overrides: raw.environment_overrides,
    })
}

fn to_path_list(items: Option<&[String]>, base_dir: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    items
        .unwrap_or(&[])
        .iter()
        .map(|item| resolve_path_like_python(base_dir, Path::new(item)))
        .collect()
}

fn to_optional_path(value: Option<&str>, base_dir: &Path) -> Result<Option<PathBuf>, ConfigError> {
    match value {
        Some(path) if !path.is_empty() => {
            resolve_path_like_python(base_dir, Path::new(path)).map(Some)
        }
        _ => Ok(None),
    }
}

fn normalize_artifact_token(value: &str) -> String {
    value
        .replace('/', "\\")
        .split('\\')
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("\\")
}

fn normalize_http_host(value: &str) -> String {
    value.trim().trim_matches('.').to_ascii_lowercase()
}

fn normalize_http_path(value: &str) -> String {
    let normalized = value.trim().replace('\\', "/");
    if normalized.is_empty() {
        "/".to_string()
    } else if normalized.starts_with('/') {
        normalized.to_ascii_lowercase()
    } else {
        format!("/{}", normalized.to_ascii_lowercase())
    }
}

fn normalize_http_verb(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn http_token_matches(value: &str, rule: &str) -> bool {
    if rule.is_empty() {
        return true;
    }
    if let Some(prefix) = rule.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        value == rule
    }
}

fn path_matches_rule(path: &str, rule: &str) -> bool {
    path == rule
        || path
            .strip_prefix(rule)
            .is_some_and(|remainder| remainder.starts_with('\\'))
}

fn parse_volume_mounts(
    mounts: Option<Vec<RawVolumeMount>>,
    base_dir: &Path,
) -> Result<Vec<VolumeMount>, ConfigError> {
    mounts
        .unwrap_or_default()
        .into_iter()
        .map(|mount| parse_volume_mount(mount, base_dir))
        .collect()
}

fn parse_http_response_rules(
    raw_rules: Option<Vec<RawHttpResponseRule>>,
) -> Result<Vec<HttpResponseRule>, ConfigError> {
    raw_rules
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, rule)| parse_http_response_rule(index, rule))
        .collect()
}

fn parse_http_response_rule(
    index: usize,
    rule: RawHttpResponseRule,
) -> Result<HttpResponseRule, ConfigError> {
    let has_inline_response = rule.status_code.is_some()
        || rule
            .headers
            .as_ref()
            .is_some_and(|headers| !headers.is_empty())
        || rule.body.is_some()
        || rule.body_hex.is_some();
    if has_inline_response
        && rule
            .responses
            .as_ref()
            .is_some_and(|items| !items.is_empty())
    {
        return Err(ConfigError::InvalidField {
            field: "http_response_rules",
            detail: format!(
                "http_response_rules[{index}] cannot mix inline response fields with `responses`"
            ),
        });
    }

    let responses = if let Some(sequence) = rule.responses {
        if sequence.is_empty() {
            vec![parse_http_response_payload(
                &format!("http_response_rules[{index}]"),
                RawHttpResponsePayload::default(),
            )?]
        } else {
            sequence
                .into_iter()
                .enumerate()
                .map(|(response_index, payload)| {
                    parse_http_response_payload(
                        &format!("http_response_rules[{index}].responses[{response_index}]"),
                        payload,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?
        }
    } else {
        vec![parse_http_response_payload(
            &format!("http_response_rules[{index}]"),
            RawHttpResponsePayload {
                status_code: rule.status_code,
                headers: rule.headers,
                body: rule.body,
                body_hex: rule.body_hex,
            },
        )?]
    };

    Ok(HttpResponseRule {
        host: rule.host.filter(|value| !value.trim().is_empty()),
        path: rule.path.filter(|value| !value.trim().is_empty()),
        verb: rule.verb.filter(|value| !value.trim().is_empty()),
        responses,
    })
}

fn parse_http_response_payload(
    location: &str,
    payload: RawHttpResponsePayload,
) -> Result<HttpResponsePayload, ConfigError> {
    if payload.body.is_some() && payload.body_hex.is_some() {
        return Err(ConfigError::InvalidField {
            field: "http_response_rules",
            detail: format!("{location} cannot set both `body` and `body_hex`"),
        });
    }

    let body = if let Some(text) = payload.body {
        text.into_bytes()
    } else if let Some(raw_hex) = payload.body_hex {
        parse_hex_bytes(&raw_hex).map_err(|detail| ConfigError::InvalidField {
            field: "http_response_rules",
            detail: format!("{location} invalid body_hex: {detail}"),
        })?
    } else {
        Vec::new()
    };

    Ok(HttpResponsePayload {
        status_code: payload.status_code.unwrap_or(200),
        headers: payload
            .headers
            .unwrap_or_default()
            .into_iter()
            .map(|header| HttpResponseHeader {
                name: header.name,
                value: header.value,
            })
            .collect(),
        body,
    })
}

fn parse_volume_mount(mount: RawVolumeMount, base_dir: &Path) -> Result<VolumeMount, ConfigError> {
    let (host_path_raw, guest_path_raw, recursive) = match mount {
        RawVolumeMount::Compact(spec) => {
            let Some((host, guest)) = split_volume_spec(&spec) else {
                return Err(ConfigError::InvalidField {
                    field: "volumes",
                    detail: format!("invalid volume spec `{spec}`"),
                });
            };
            (host.to_string(), guest.to_string(), None)
        }
        RawVolumeMount::Detailed {
            host_path,
            guest_path,
            recursive,
        } => (host_path, guest_path, recursive),
    };

    let host_path = resolve_path_like_python(base_dir, Path::new(host_path_raw.trim()))?;
    let guest_path = normalize_guest_volume_path(guest_path_raw.trim()).ok_or_else(|| {
        ConfigError::InvalidField {
            field: "volumes",
            detail: format!("invalid guest path `{}`", guest_path_raw.trim()),
        }
    })?;

    Ok(VolumeMount {
        host_path,
        guest_path,
        recursive: recursive.unwrap_or(true),
    })
}

fn split_volume_spec(spec: &str) -> Option<(&str, &str)> {
    let bytes = spec.as_bytes();
    for index in 0..bytes.len().saturating_sub(3) {
        if bytes[index] == b':'
            && bytes[index + 1].is_ascii_alphabetic()
            && bytes[index + 2] == b':'
            && matches!(bytes[index + 3], b'\\' | b'/')
        {
            let host = spec[..index].trim();
            let guest = spec[index + 1..].trim();
            if !host.is_empty() && !guest.is_empty() {
                return Some((host, guest));
            }
            return None;
        }
    }

    let (host, guest) = spec.split_once(':')?;
    let host = host.trim();
    let guest = guest.trim();
    (!host.is_empty() && !guest.is_empty()).then_some((host, guest))
}

fn normalize_guest_volume_path(path: &str) -> Option<String> {
    let normalized = path.trim().replace('/', "\\");
    is_windows_absolute_guest_path(&normalized).then_some(normalized)
}

fn is_windows_absolute_guest_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

fn parse_entry_args(items: Option<Vec<Value>>) -> Result<Vec<EntryArgument>, ConfigError> {
    items
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, value)| parse_entry_arg(index, value))
        .collect()
}

fn parse_entry_arg(index: usize, value: Value) -> Result<EntryArgument, ConfigError> {
    match value {
        Value::Null => Ok(EntryArgument::Null),
        Value::Bool(flag) => Ok(EntryArgument::Value(flag as u64)),
        Value::Number(number) => {
            number
                .as_u64()
                .map(EntryArgument::Value)
                .ok_or_else(|| ConfigError::InvalidField {
                    field: "entry_args",
                    detail: format!("entry_args[{index}] must be a non-negative integer"),
                })
        }
        Value::String(text) => {
            if let Some(parsed) = parse_integer_literal(&text) {
                Ok(EntryArgument::Value(parsed))
            } else {
                Ok(EntryArgument::AnsiString(text))
            }
        }
        Value::Array(items) => Ok(EntryArgument::Bytes(parse_byte_array(index, &items)?)),
        Value::Object(map) => {
            let Some(kind) = map.get("type").and_then(Value::as_str) else {
                return Err(ConfigError::InvalidField {
                    field: "entry_args",
                    detail: format!("entry_args[{index}] object arguments require a `type` field"),
                });
            };
            match kind.to_ascii_lowercase().as_str() {
                "value" | "u32" | "u64" | "int" | "ptr" | "pointer" => {
                    let Some(raw_value) = map.get("value") else {
                        return Err(ConfigError::InvalidField {
                            field: "entry_args",
                            detail: format!(
                                "entry_args[{index}] type `{kind}` requires a `value` field"
                            ),
                        });
                    };
                    parse_scalar_u64(index, raw_value).map(EntryArgument::Value)
                }
                "null" => Ok(EntryArgument::Null),
                "string" | "ansi" | "cstr" => {
                    parse_string_field(index, &map, "value").map(EntryArgument::AnsiString)
                }
                "wstring" | "wide" | "utf16" => {
                    parse_string_field(index, &map, "value").map(EntryArgument::WideString)
                }
                "bytes" | "buffer" => {
                    if let Some(raw_hex) = map.get("hex").and_then(Value::as_str) {
                        parse_hex_bytes(raw_hex)
                            .map(EntryArgument::Bytes)
                            .map_err(|detail| ConfigError::InvalidField {
                                field: "entry_args",
                                detail: format!("entry_args[{index}] invalid hex buffer: {detail}"),
                            })
                    } else if let Some(raw_value) = map.get("value") {
                        match raw_value {
                            Value::Array(items) => {
                                parse_byte_array(index, items).map(EntryArgument::Bytes)
                            }
                            Value::String(text) => {
                                Ok(EntryArgument::Bytes(text.as_bytes().to_vec()))
                            }
                            _ => Err(ConfigError::InvalidField {
                                field: "entry_args",
                                detail: format!(
                                    "entry_args[{index}] bytes value must be an array or string"
                                ),
                            }),
                        }
                    } else {
                        Err(ConfigError::InvalidField {
                            field: "entry_args",
                            detail: format!(
                                "entry_args[{index}] type `{kind}` requires `value` or `hex`"
                            ),
                        })
                    }
                }
                _ => Err(ConfigError::InvalidField {
                    field: "entry_args",
                    detail: format!("entry_args[{index}] uses unsupported type `{kind}`"),
                }),
            }
        }
    }
}

fn parse_scalar_u64(index: usize, value: &Value) -> Result<u64, ConfigError> {
    match value {
        Value::Null => Ok(0),
        Value::Bool(flag) => Ok(*flag as u64),
        Value::Number(number) => number.as_u64().ok_or_else(|| ConfigError::InvalidField {
            field: "entry_args",
            detail: format!("entry_args[{index}] numeric values must be non-negative"),
        }),
        Value::String(text) => {
            parse_integer_literal(text).ok_or_else(|| ConfigError::InvalidField {
                field: "entry_args",
                detail: format!("entry_args[{index}] could not parse integer literal `{text}`"),
            })
        }
        _ => Err(ConfigError::InvalidField {
            field: "entry_args",
            detail: format!("entry_args[{index}] scalar values must be number, bool, or string"),
        }),
    }
}

fn parse_string_field(
    index: usize,
    map: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, ConfigError> {
    map.get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| ConfigError::InvalidField {
            field: "entry_args",
            detail: format!("entry_args[{index}] requires string field `{key}`"),
        })
}

fn parse_byte_array(index: usize, items: &[Value]) -> Result<Vec<u8>, ConfigError> {
    items
        .iter()
        .enumerate()
        .map(|(offset, item)| {
            let value = parse_scalar_u64(index, item)?;
            u8::try_from(value).map_err(|_| ConfigError::InvalidField {
                field: "entry_args",
                detail: format!("entry_args[{index}][{offset}] must fit in one byte"),
            })
        })
        .collect()
}

fn parse_integer_literal(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    trimmed.parse::<u64>().ok()
}

fn parse_hex_bytes(raw_hex: &str) -> Result<Vec<u8>, String> {
    let compact = raw_hex
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != ',' && *ch != '_')
        .collect::<String>();
    if compact.len() % 2 != 0 {
        return Err("hex string must contain an even number of digits".to_string());
    }
    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let pair = std::str::from_utf8(chunk).map_err(|_| "hex string is not valid ASCII")?;
            u8::from_str_radix(pair, 16).map_err(|_| format!("invalid byte `{pair}`"))
        })
        .collect()
}

fn resolve_path_like_python(base_dir: &Path, path: &Path) -> Result<PathBuf, ConfigError> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };
    absolute(&candidate).map_err(|source| ConfigError::ResolvePath {
        path: candidate,
        source,
    })
}
