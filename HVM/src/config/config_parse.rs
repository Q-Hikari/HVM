use super::*;
use serde::Deserialize;

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
    prologue_source_paths: Option<Vec<String>>,
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
    api_log_include_context: Option<bool>,
    api_log_stack_words: Option<usize>,
    api_log_string_limit: Option<usize>,
    console_output_to_console: Option<bool>,
    console_output_path: Option<String>,
    unknown_api_policy: Option<String>,
    stack_reserve_size: Option<u64>,
    max_instructions: Option<u64>,
    process_command_line: Option<String>,
    command_line: Option<String>,
    environment_profile: Option<String>,
    environment_overrides: Option<EnvironmentOverrides>,
    interception_rules: Option<RawInterceptionRules>,
    observation_checkpoints: Option<Vec<RawCheckpointConfig>>,
    exit_on_unsupported_hook: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawCheckpointConfig {
    instruction_count: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct RawModuleSettings {
    modules_always_exist: Option<bool>,
    functions_always_exist: Option<bool>,
    module_directory_x86: Option<String>,
    module_directory_x64: Option<String>,
}

// ---------------------------------------------------------------------------
// Raw interception rules (serde deserialization shapes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub(crate) struct RawInterceptionRules {
    registry: Option<Vec<RawRegistryInterceptionRule>>,
    files: Option<Vec<RawFileInterceptionRule>>,
    system: Option<Vec<RawSystemInterceptionRule>>,
    devices: Option<Vec<RawDeviceInterceptionRule>>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawRegistryInterceptionRule {
    path: String,
    value_name: Option<String>,
    action: String,
    #[serde(default)]
    error_code: Option<u32>,
    #[serde(default)]
    #[allow(dead_code)]
    value_type: Option<u32>,
    #[serde(default)]
    string: Option<String>,
    #[serde(default)]
    dword: Option<u32>,
    #[serde(default)]
    qword: Option<u64>,
    #[serde(default)]
    binary_hex: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawFileInterceptionRule {
    path: String,
    action: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    content_hex: Option<String>,
    #[serde(default)]
    host_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSystemInterceptionRule {
    query: String,
    value: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct RawHttpResponseRule {
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
pub(crate) struct RawHttpResponsePayload {
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
pub(crate) enum RawVolumeMount {
    Compact(String),
    Detailed {
        host_path: String,
        guest_path: String,
        recursive: Option<bool>,
    },
}

/// Loads JSON config files with default values and path resolution.
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
    let main_module = resolve_path(project_base, Path::new(&main_module_raw))?;
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
        prologue_source_paths: to_path_list(raw.prologue_source_paths.as_deref(), project_base)?,
        volumes: parse_volume_mounts(raw.volumes, project_base)?,
        auto_mount_module_dirs: raw.auto_mount_module_dirs.unwrap_or(true),
        allowed_read_dirs: to_path_list(raw.allowed_read_dirs.as_deref(), project_base)?,
        blocked_read_dirs: to_path_list(raw.blocked_read_dirs.as_deref(), project_base)?,
        hidden_device_paths: raw.hidden_device_paths.unwrap_or_default(),
        hidden_registry_keys: raw.hidden_registry_keys.unwrap_or_default(),
        http_response_rules: parse_http_response_rules(raw.http_response_rules)?,
        sandbox_output_dir: resolve_path(
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
        api_log_include_context: raw.api_log_include_context.unwrap_or(false),
        api_log_stack_words: raw.api_log_stack_words.unwrap_or(4).min(32),
        api_log_string_limit: raw.api_log_string_limit.unwrap_or(160),
        console_output_to_console: raw.console_output_to_console.unwrap_or(false),
        console_output_path: to_optional_path(raw.console_output_path.as_deref(), project_base)?,
        unknown_api_policy: raw
            .unknown_api_policy
            .unwrap_or_else(|| "log_zero".to_string()),
        stack_reserve_size: raw.stack_reserve_size.filter(|value| *value != 0),
        max_instructions: raw.max_instructions.unwrap_or(1_000_000),
        command_line: process_command_line.unwrap_or_else(|| raw.command_line.unwrap_or_default()),
        environment_profile: to_optional_path(raw.environment_profile.as_deref(), project_base)?,
        environment_overrides: raw.environment_overrides,
        interception_rules: parse_interception_rules(raw.interception_rules, project_base)?,
        observation_checkpoints: raw
            .observation_checkpoints
            .unwrap_or_default()
            .into_iter()
            .map(|cp| cp.instruction_count)
            .collect(),
        exit_on_unsupported_hook: raw.exit_on_unsupported_hook.unwrap_or(false),
    })
}

pub(super) fn to_path_list(
    items: Option<&[String]>,
    base_dir: &Path,
) -> Result<Vec<PathBuf>, ConfigError> {
    items
        .unwrap_or(&[])
        .iter()
        .map(|item| resolve_path(base_dir, Path::new(item)))
        .collect()
}

pub(super) fn to_optional_path(
    value: Option<&str>,
    base_dir: &Path,
) -> Result<Option<PathBuf>, ConfigError> {
    match value {
        Some(path) if !path.is_empty() => resolve_path(base_dir, Path::new(path)).map(Some),
        _ => Ok(None),
    }
}

pub(super) fn normalize_artifact_token(value: &str) -> String {
    value
        .replace('/', "\\")
        .split('\\')
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("\\")
}

pub(super) fn normalize_http_host(value: &str) -> String {
    value.trim().trim_matches('.').to_ascii_lowercase()
}

pub(super) fn normalize_http_path(value: &str) -> String {
    let normalized = value.trim().replace('\\', "/");
    if normalized.is_empty() {
        "/".to_string()
    } else if normalized.starts_with('/') {
        normalized.to_ascii_lowercase()
    } else {
        format!("/{}", normalized.to_ascii_lowercase())
    }
}

pub(super) fn normalize_http_verb(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

pub(super) fn http_token_matches(value: &str, rule: &str) -> bool {
    if rule.is_empty() {
        return true;
    }
    if let Some(prefix) = rule.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        value == rule
    }
}

pub(super) fn path_matches_rule(path: &str, rule: &str) -> bool {
    path == rule
        || path
            .strip_prefix(rule)
            .is_some_and(|remainder| remainder.starts_with('\\'))
}

pub(super) fn parse_volume_mounts(
    mounts: Option<Vec<RawVolumeMount>>,
    base_dir: &Path,
) -> Result<Vec<VolumeMount>, ConfigError> {
    mounts
        .unwrap_or_default()
        .into_iter()
        .map(|mount| parse_volume_mount(mount, base_dir))
        .collect()
}

pub(super) fn parse_http_response_rules(
    raw_rules: Option<Vec<RawHttpResponseRule>>,
) -> Result<Vec<HttpResponseRule>, ConfigError> {
    raw_rules
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, rule)| parse_http_response_rule(index, rule))
        .collect()
}

pub(super) fn parse_http_response_rule(
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

pub(super) fn parse_http_response_payload(
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

// ---------------------------------------------------------------------------
// Interception rules parsing
// ---------------------------------------------------------------------------

pub(super) fn parse_interception_rules(
    raw: Option<RawInterceptionRules>,
    base_dir: &Path,
) -> Result<InterceptionRules, ConfigError> {
    let raw = match raw {
        Some(raw) => raw,
        None => return Ok(InterceptionRules::default()),
    };
    let registry = raw
        .registry
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, rule)| parse_registry_interception_rule(index, rule))
        .collect::<Result<Vec<_>, _>>()?;
    let files = raw
        .files
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, rule)| parse_file_interception_rule(index, rule, base_dir))
        .collect::<Result<Vec<_>, _>>()?;
    let system = raw
        .system
        .unwrap_or_default()
        .into_iter()
        .map(|rule| SystemInterceptionRule {
            query: rule.query,
            value: rule.value,
        })
        .collect();
    let devices = raw
        .devices
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, rule)| parse_device_interception_rule(index, rule))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(InterceptionRules {
        registry,
        files,
        system,
        devices,
    })
}

pub(super) fn parse_registry_interception_rule(
    index: usize,
    rule: RawRegistryInterceptionRule,
) -> Result<RegistryInterceptionRule, ConfigError> {
    let action = match rule.action.to_ascii_lowercase().as_str() {
        "not_found" | "notfound" => InterceptionAction::NotFound,
        "access_denied" | "accessdenied" => InterceptionAction::AccessDenied,
        "error" => InterceptionAction::ErrorCode(rule.error_code.unwrap_or(5)),
        "return_data" | "returndata" | "return" => {
            let value =
                parse_interception_value(&format!("interception_rules.registry[{index}]"), &rule)?;
            InterceptionAction::ReturnData(value)
        }
        other => {
            return Err(ConfigError::InvalidField {
                field: "interception_rules",
                detail: format!(
                    "interception_rules.registry[{index}] unsupported action `{other}`"
                ),
            })
        }
    };
    Ok(RegistryInterceptionRule {
        path: normalize_registry_interception_path(&rule.path),
        value_name: rule.value_name.filter(|v| !v.is_empty()),
        action,
    })
}

pub(super) fn parse_interception_value(
    location: &str,
    rule: &RawRegistryInterceptionRule,
) -> Result<InterceptionValue, ConfigError> {
    // Check for exactly one value payload.
    let mut found = Vec::new();
    if rule.string.is_some() {
        found.push("string");
    }
    if rule.dword.is_some() {
        found.push("dword");
    }
    if rule.qword.is_some() {
        found.push("qword");
    }
    if rule.binary_hex.is_some() {
        found.push("binary_hex");
    }
    if found.is_empty() {
        return Err(ConfigError::InvalidField {
            field: "interception_rules",
            detail: format!("{location} with action return_data must specify one of: string, dword, qword, binary_hex"),
        });
    }
    if found.len() > 1 {
        return Err(ConfigError::InvalidField {
            field: "interception_rules",
            detail: format!(
                "{location} specifies multiple value types: {} — use only one",
                found.join(", ")
            ),
        });
    }
    if let Some(value) = &rule.string {
        Ok(InterceptionValue::String(value.clone()))
    } else if let Some(value) = rule.dword {
        Ok(InterceptionValue::Dword(value))
    } else if let Some(value) = rule.qword {
        Ok(InterceptionValue::Qword(value))
    } else if let Some(hex) = &rule.binary_hex {
        parse_hex_bytes(hex)
            .map(InterceptionValue::Bytes)
            .map_err(|detail| ConfigError::InvalidField {
                field: "interception_rules",
                detail: format!("{location} invalid binary_hex: {detail}"),
            })
    } else {
        unreachable!()
    }
}

pub(super) fn parse_file_interception_rule(
    index: usize,
    rule: RawFileInterceptionRule,
    base_dir: &Path,
) -> Result<FileInterceptionRule, ConfigError> {
    let action = match rule.action.to_ascii_lowercase().as_str() {
        "not_found" | "notfound" => FileInterceptionAction::NotFound,
        "access_denied" | "accessdenied" => FileInterceptionAction::AccessDenied,
        "return_content" | "returncontent" => {
            if rule.content.is_some() && rule.content_hex.is_some() {
                return Err(ConfigError::InvalidField {
                    field: "interception_rules",
                    detail: format!(
                        "interception_rules.files[{index}] cannot set both content and content_hex"
                    ),
                });
            }
            let data = if let Some(text) = rule.content {
                text.into_bytes()
            } else if let Some(hex) = rule.content_hex {
                parse_hex_bytes(&hex).map_err(|detail| ConfigError::InvalidField {
                    field: "interception_rules",
                    detail: format!(
                        "interception_rules.files[{index}] invalid content_hex: {detail}"
                    ),
                })?
            } else {
                Vec::new()
            };
            FileInterceptionAction::ReturnContent { data }
        }
        "redirect" => {
            let host_path_raw = rule.host_path.ok_or_else(|| ConfigError::InvalidField {
                field: "interception_rules",
                detail: format!(
                    "interception_rules.files[{index}] action redirect requires host_path"
                ),
            })?;
            let host_path = resolve_path(base_dir, Path::new(host_path_raw.trim()))?;
            FileInterceptionAction::Redirect { host_path }
        }
        other => {
            return Err(ConfigError::InvalidField {
                field: "interception_rules",
                detail: format!("interception_rules.files[{index}] unsupported action `{other}`"),
            })
        }
    };
    Ok(FileInterceptionRule {
        path: normalize_file_interception_path(&rule.path),
        action,
    })
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawDeviceInterceptionRule {
    path: String,
    #[serde(default)]
    ioctl_code: Option<String>,
    #[serde(default)]
    output_hex: Option<String>,
    #[serde(default)]
    output: Option<Vec<u8>>,
    #[serde(default)]
    bytes_returned: Option<u32>,
}

pub(super) fn parse_device_interception_rule(
    index: usize,
    rule: RawDeviceInterceptionRule,
) -> Result<DeviceInterceptionRule, ConfigError> {
    let ioctl_code = if let Some(code_str) = &rule.ioctl_code {
        let code_str = code_str.trim();
        if code_str.is_empty() {
            None
        } else {
            let stripped = code_str.strip_prefix("0x").unwrap_or(code_str);
            Some(
                u64::from_str_radix(stripped, 16).map_err(|_| ConfigError::InvalidField {
                    field: "interception_rules",
                    detail: format!("devices[{index}] invalid ioctl_code `{code_str}`"),
                })?,
            )
        }
    } else {
        None
    };

    let output = if let Some(hex) = &rule.output_hex {
        let compact: String = hex
            .chars()
            .filter(|c| !c.is_ascii_whitespace() && *c != ',' && *c != ';')
            .collect();
        if compact.len() % 2 != 0 {
            return Err(ConfigError::InvalidField {
                field: "interception_rules",
                detail: format!("devices[{index}] output_hex length must be even"),
            });
        }
        (0..compact.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&compact[i..i + 2], 16).map_err(|_| ConfigError::InvalidField {
                    field: "interception_rules",
                    detail: format!("devices[{index}] invalid hex in output_hex"),
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    } else if let Some(bytes) = &rule.output {
        bytes.clone()
    } else {
        vec![1u8, 0, 0, 0] // default: non-zero DWORD
    };

    let bytes_returned = rule.bytes_returned.unwrap_or(output.len() as u32);
    Ok(DeviceInterceptionRule {
        path: normalize_file_interception_path(&rule.path),
        ioctl_code,
        output,
        bytes_returned,
    })
}

/// Normalize a registry path for interception matching: collapse slashes, lowercase.
pub(super) fn normalize_registry_interception_path(path: &str) -> String {
    let normalized = path
        .replace('/', "\\")
        .split('\\')
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("\\");
    // Expand well-known root abbreviations.
    let normalized = if let Some(rest) = normalized
        .strip_prefix("hklm\\")
        .or_else(|| normalized.strip_prefix("hkey_local_machine\\"))
    {
        format!("hkey_local_machine\\{}", rest)
    } else if let Some(rest) = normalized
        .strip_prefix("hkcu\\")
        .or_else(|| normalized.strip_prefix("hkey_current_user\\"))
    {
        format!("hkey_current_user\\{}", rest)
    } else if let Some(rest) = normalized
        .strip_prefix("hkcr\\")
        .or_else(|| normalized.strip_prefix("hkey_classes_root\\"))
    {
        format!("hkey_classes_root\\{}", rest)
    } else if let Some(rest) = normalized
        .strip_prefix("hku\\")
        .or_else(|| normalized.strip_prefix("hkey_users\\"))
    {
        format!("hkey_users\\{}", rest)
    } else if let Some(rest) = normalized
        .strip_prefix("hkcc\\")
        .or_else(|| normalized.strip_prefix("hkey_current_config\\"))
    {
        format!("hkey_current_config\\{}", rest)
    } else {
        normalized
    };
    normalized
}

/// Normalize a file path for interception matching: collapse slashes, uppercase drive letter.
pub(super) fn normalize_file_interception_path(path: &str) -> String {
    path.replace('/', "\\")
        .split('\\')
        .filter(|part| !part.is_empty())
        .enumerate()
        .map(|(i, part)| {
            if i == 0 && part.len() == 2 && part.as_bytes()[1] == b':' {
                part.to_ascii_uppercase()
            } else {
                part.to_ascii_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join("\\")
}

pub(super) fn parse_volume_mount(
    mount: RawVolumeMount,
    base_dir: &Path,
) -> Result<VolumeMount, ConfigError> {
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

    let host_path = resolve_path(base_dir, Path::new(host_path_raw.trim()))?;
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

pub(super) fn split_volume_spec(spec: &str) -> Option<(&str, &str)> {
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

pub(super) fn normalize_guest_volume_path(path: &str) -> Option<String> {
    let normalized = path.trim().replace('/', "\\");
    is_windows_absolute_guest_path(&normalized).then_some(normalized)
}

pub(super) fn is_windows_absolute_guest_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

pub(super) fn parse_entry_args(
    items: Option<Vec<Value>>,
) -> Result<Vec<EntryArgument>, ConfigError> {
    items
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, value)| parse_entry_arg(index, value))
        .collect()
}

pub(super) fn parse_entry_arg(index: usize, value: Value) -> Result<EntryArgument, ConfigError> {
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

pub(super) fn parse_scalar_u64(index: usize, value: &Value) -> Result<u64, ConfigError> {
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

pub(super) fn parse_string_field(
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

pub(super) fn parse_byte_array(index: usize, items: &[Value]) -> Result<Vec<u8>, ConfigError> {
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

pub(super) fn parse_integer_literal(text: &str) -> Option<u64> {
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

pub(super) fn parse_hex_bytes(raw_hex: &str) -> Result<Vec<u8>, String> {
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

pub(super) fn resolve_path(base_dir: &Path, path: &Path) -> Result<PathBuf, ConfigError> {
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

// ---------------------------------------------------------------------------
// Sandbox config builder — creates EngineConfig without a JSON file
// ---------------------------------------------------------------------------

impl EngineConfig {
    /// Build an `EngineConfig` for the sandbox `analyze` command.
    ///
    /// `profile_name` is either a bare name like `"win10_21h2_x64"` (resolved
    /// against `configs/profiles/`) or an absolute/relative path to a profile JSON.
    pub fn for_sandbox(
        sample_path: &Path,
        profile_name: &str,
        max_instructions: u64,
        output_dir: &Path,
        project_root: &Path,
    ) -> Result<Self, ConfigError> {
        let sample_path = absolute(sample_path).map_err(|source| ConfigError::ResolvePath {
            path: sample_path.to_path_buf(),
            source,
        })?;
        let sample_parent = sample_path.parent().unwrap_or(Path::new("."));
        let output_dir = absolute(output_dir).map_err(|source| ConfigError::ResolvePath {
            path: output_dir.to_path_buf(),
            source,
        })?;

        let mut module_search_paths = vec![
            sample_parent.to_path_buf(),
            PathBuf::from("C:/Windows/System32"),
            PathBuf::from("C:/Windows/SysWOW64"),
        ];
        // Auto-include system_dll directory if it exists relative to project root.
        let system_dll_dir = project_root.join("system_dll");
        if system_dll_dir.is_dir() {
            module_search_paths.push(system_dll_dir);
        }

        let api_log_dir = output_dir.join("logs");
        let sample_file_name = sample_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "sample".to_string());
        let log_prefix = sample_file_name.clone();

        Ok(Self {
            main_module: sample_path.clone(),
            process_image: Some(sample_path.clone()),
            parent_process_image: None,
            parent_process_pid: None,
            parent_process_command_line: None,
            entry_module: None,
            entry_export: None,
            entry_ordinal: None,
            entry_args: Vec::new(),
            module_search_paths,
            modules_always_exist: true,
            functions_always_exist: true,
            module_directory_x86: None,
            module_directory_x64: None,
            whitelist_modules: BTreeSet::new(),
            preload_modules: Vec::new(),
            prologue_source_paths: Vec::new(),
            volumes: vec![VolumeMount {
                host_path: sample_parent.to_path_buf(),
                guest_path: "C:\\".to_string(),
                recursive: false,
            }],
            auto_mount_module_dirs: true,
            allowed_read_dirs: vec![
                sample_parent.to_path_buf(),
                PathBuf::from("C:/Windows/System32"),
                PathBuf::from("C:/Windows/SysWOW64"),
            ],
            blocked_read_dirs: vec![PathBuf::from("C:/Users")],
            hidden_device_paths: Vec::new(),
            hidden_registry_keys: Vec::new(),
            http_response_rules: Vec::new(),
            sandbox_output_dir: output_dir.join("sandbox"),
            trace_api_calls: true,
            trace_native_events: false,
            api_log_path: Some(api_log_dir.join(format!("{log_prefix}.api.log"))),
            api_jsonl_path: Some(api_log_dir.join(format!("{log_prefix}.api.jsonl"))),
            api_human_log_path: Some(api_log_dir.join(format!("{log_prefix}.api.human.log"))),
            api_log_to_console: false,
            api_log_include_return: true,
            api_log_include_context: false,
            api_log_stack_words: 4,
            api_log_string_limit: 512,
            console_output_to_console: false,
            console_output_path: Some(api_log_dir.join(format!("{log_prefix}.console.log"))),
            unknown_api_policy: "log_zero".to_string(),
            stack_reserve_size: None,
            max_instructions,
            command_line: sample_file_name,
            environment_profile: resolve_profile_path(profile_name, project_root)?,
            environment_overrides: None,
            interception_rules: InterceptionRules::default(),
            observation_checkpoints: Vec::new(),
            exit_on_unsupported_hook: false,
        })
    }
}

/// Resolve a profile name to a path.
///
/// - If `name` looks like an existing file path, use it directly.
/// - Otherwise, look for `configs/profiles/{name}.json` relative to `project_root`.
pub(super) fn resolve_profile_path(
    name: &str,
    project_root: &Path,
) -> Result<Option<PathBuf>, ConfigError> {
    let candidate = Path::new(name);
    if candidate.is_absolute() && candidate.exists() {
        return Ok(Some(candidate.to_path_buf()));
    }
    let relative = project_root
        .join("configs/profiles")
        .join(format!("{name}.json"));
    if relative.exists() {
        return Ok(Some(absolute(&relative).map_err(|source| {
            ConfigError::ResolvePath {
                path: relative.clone(),
                source,
            }
        })?));
    }
    // If not found, return None — the engine will use the default profile.
    Ok(None)
}
