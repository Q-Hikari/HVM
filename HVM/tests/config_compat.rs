use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::{load_config, EntryArgument};
use hvm::samples::{first_exported_sample, first_runnable_sample};

fn runtime_sample() -> hvm::samples::SampleDescriptor {
    first_runnable_sample()
        .unwrap()
        .expect("expected at least one runnable x86 sample")
}

fn exported_sample() -> hvm::samples::SampleDescriptor {
    first_exported_sample()
        .unwrap()
        .expect("expected at least one exported sample")
}

#[test]
fn load_config_matches_python_relative_path_rules() {
    let sample = runtime_sample();
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("configs")
        .join("sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();

    assert!(config
        .main_module
        .ends_with(Path::new("Sample").join(&sample.name)));
    assert!(config
        .module_search_paths
        .iter()
        .any(|path| path.ends_with(Path::new("Sample"))));
    assert!(config.whitelist_modules.is_empty());
    assert_eq!(config.max_instructions, 10_000_000);
}

#[test]
fn load_config_applies_python_default_values() {
    let sample = runtime_sample();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path =
        std::env::temp_dir().join(format!("hvm-hikari-virtual-engine-config-{timestamp}.json"));
    let main_module = sample.path;

    fs::write(
        &config_path,
        format!(
            "{{\"main_module\":\"{}\"}}",
            main_module.to_string_lossy().replace('\\', "\\\\")
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();

    assert_eq!(config.max_instructions, 1_000_000);
    assert_eq!(config.command_line, "");
    assert_eq!(config.unknown_api_policy, "log_zero");
    assert!(!config.trace_api_calls);
    assert!(!config.trace_native_events);
    assert!(config.modules_always_exist);
    assert!(config.functions_always_exist);
    assert_eq!(config.module_directory_x86, None);
    assert_eq!(config.module_directory_x64, None);

    fs::remove_file(config_path).unwrap();
}

#[test]
fn load_config_keeps_native_trace_disabled_by_default_even_with_api_trace() {
    let sample = runtime_sample();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-native-trace-config-{timestamp}.json"
    ));

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"trace_api_calls\":true",
                "}}"
            ),
            sample.path.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();
    assert!(config.trace_api_calls);
    assert!(!config.trace_native_events);

    fs::remove_file(config_path).unwrap();
}

#[test]
fn load_config_allows_disabling_native_trace_independently() {
    let sample = runtime_sample();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-native-trace-optout-{timestamp}.json"
    ));

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"trace_api_calls\":true,",
                "\"trace_native_events\":false",
                "}}"
            ),
            sample.path.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();
    assert!(config.trace_api_calls);
    assert!(!config.trace_native_events);

    fs::remove_file(config_path).unwrap();
}

#[test]
fn load_config_parses_dll_export_entry_and_typed_arguments() {
    let dll_sample = exported_sample();
    let host_sample = runtime_sample();
    let export_name = dll_sample
        .first_export()
        .expect("expected exported sample to expose at least one export")
        .to_string();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-dll-config-{timestamp}.json"
    ));
    let dll_path = dll_sample.path;
    let host_path = host_sample.path;

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"process_image\":\"{}\",",
                "\"entry_module\":\"{}\",",
                "\"entry_export\":\"{}\",",
                "\"entry_args\":[",
                "\"0x1234\",",
                "{{\"type\":\"string\",\"value\":\"ansi-arg\"}},",
                "{{\"type\":\"wstring\",\"value\":\"宽参数\"}},",
                "{{\"type\":\"bytes\",\"hex\":\"41 42 43\"}},",
                "null",
                "]",
                "}}"
            ),
            dll_path.to_string_lossy().replace('\\', "\\\\"),
            host_path.to_string_lossy().replace('\\', "\\\\"),
            dll_path.to_string_lossy().replace('\\', "\\\\"),
            export_name,
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();

    assert_eq!(config.process_image.as_ref(), Some(&host_path));
    assert_eq!(config.entry_module.as_ref(), Some(&dll_path));
    assert_eq!(config.entry_export.as_deref(), Some(export_name.as_str()));
    assert_eq!(config.entry_ordinal, None);
    assert_eq!(
        config.entry_args,
        vec![
            EntryArgument::Value(0x1234),
            EntryArgument::AnsiString("ansi-arg".to_string()),
            EntryArgument::WideString("宽参数".to_string()),
            EntryArgument::Bytes(vec![0x41, 0x42, 0x43]),
            EntryArgument::Null,
        ]
    );

    fs::remove_file(config_path).unwrap();
}

#[test]
fn load_config_parses_hidden_artifact_rules() {
    let sample = runtime_sample();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-hidden-artifacts-{timestamp}.json"
    ));

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"hidden_device_paths\":[\"\\\\\\\\.\\\\VBoxMiniRdrDN\"],",
                "\"hidden_registry_keys\":[\"SOFTWARE\\\\VMware, Inc.\\\\VMware Tools\"]",
                "}}"
            ),
            sample.path.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();

    assert_eq!(
        config.hidden_device_paths,
        vec![String::from(r"\\.\VBoxMiniRdrDN")]
    );
    assert_eq!(
        config.hidden_registry_keys,
        vec![String::from(r"SOFTWARE\VMware, Inc.\VMware Tools")]
    );

    fs::remove_file(config_path).unwrap();
}

#[test]
fn load_config_parses_http_response_rules() {
    let sample = runtime_sample();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-http-response-rules-{timestamp}.json"
    ));

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"http_response_rules\":[{{",
                "\"host\":\"example.com\",",
                "\"path\":\"/dashBoardRead.php\",",
                "\"verb\":\"GET\",",
                "\"status_code\":200,",
                "\"headers\":[{{\"name\":\"Content-Type\",\"value\":\"text/plain\"}}],",
                "\"body\":\"hello world\"",
                "}}]",
                "}}"
            ),
            sample.path.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();

    assert_eq!(config.http_response_rules.len(), 1);
    let rule = &config.http_response_rules[0];
    assert_eq!(rule.host.as_deref(), Some("example.com"));
    assert_eq!(rule.path.as_deref(), Some("/dashBoardRead.php"));
    assert_eq!(rule.verb.as_deref(), Some("GET"));
    assert_eq!(rule.responses.len(), 1);
    assert_eq!(rule.responses[0].status_code, 200);
    assert_eq!(rule.responses[0].headers.len(), 1);
    assert_eq!(rule.responses[0].headers[0].name, "Content-Type");
    assert_eq!(rule.responses[0].headers[0].value, "text/plain");
    assert_eq!(rule.responses[0].body, b"hello world");

    fs::remove_file(config_path).unwrap();
}

#[test]
fn load_config_parses_http_response_sequences() {
    let sample = runtime_sample();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-http-response-sequence-{timestamp}.json"
    ));

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"http_response_rules\":[{{",
                "\"host\":\"example.com\",",
                "\"path\":\"/poll\",",
                "\"verb\":\"GET\",",
                "\"responses\":[",
                "{{\"status_code\":204}},",
                "{{\"status_code\":200,\"body\":\"second\"}}",
                "]",
                "}}]",
                "}}"
            ),
            sample.path.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();

    assert_eq!(config.http_response_rules.len(), 1);
    let rule = &config.http_response_rules[0];
    assert_eq!(rule.responses.len(), 2);
    assert_eq!(rule.responses[0].status_code, 204);
    assert!(rule.responses[0].body.is_empty());
    assert_eq!(rule.responses[1].status_code, 200);
    assert_eq!(rule.responses[1].body, b"second");

    fs::remove_file(config_path).unwrap();
}

#[test]
fn load_config_parses_parent_process_overrides() {
    let sample = runtime_sample();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-parent-config-{timestamp}.json"
    ));
    let main_module = sample.path.clone();
    let parent_image = sample.path;

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"parent_process_image\":\"{}\",",
                "\"parent_process_pid\":4660,",
                "\"parent_process_command_line\":\"\\\"{}\\\" /embedding\"",
                "}}"
            ),
            main_module.to_string_lossy().replace('\\', "\\\\"),
            parent_image.to_string_lossy().replace('\\', "\\\\"),
            parent_image.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();

    assert_eq!(config.parent_process_image.as_ref(), Some(&parent_image));
    assert_eq!(config.parent_process_pid, Some(4660));
    let expected_command_line = format!("\"{}\" /embedding", parent_image.to_string_lossy());
    assert_eq!(
        config.parent_process_command_line.as_deref(),
        Some(expected_command_line.as_str())
    );

    fs::remove_file(config_path).unwrap();
}

#[test]
fn load_config_resolves_environment_profile_path() {
    let sample = runtime_sample();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-profile-config-{timestamp}"
    ));
    let config_dir = root.join("configs");
    let profile_dir = root.join("profiles");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&profile_dir).unwrap();

    let profile_path = profile_dir.join("snapshot.json");
    fs::write(
        &profile_path,
        "{\"machine\":{\"computer_name\":\"TESTBOX\"}}",
    )
    .unwrap();

    let config_path = config_dir.join("sample.json");
    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"environment_profile\":\"profiles/snapshot.json\"",
                "}}"
            ),
            sample.path.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();
    assert_eq!(config.environment_profile.as_ref(), Some(&profile_path));

    fs::remove_file(config_path).unwrap();
    fs::remove_file(profile_path).unwrap();
    fs::remove_dir(profile_dir).unwrap();
    fs::remove_dir(config_dir).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn load_config_parses_volume_mounts_from_compact_and_object_forms() {
    let sample = runtime_sample();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-volumes-config-{timestamp}"
    ));
    let config_dir = root.join("configs");
    let mounts_dir = root.join("mounts");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&mounts_dir).unwrap();

    let compact_host = mounts_dir.join("compact");
    let object_host = mounts_dir.join("object");
    fs::create_dir_all(&compact_host).unwrap();
    fs::create_dir_all(&object_host).unwrap();

    let config_path = config_dir.join("sample.json");
    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"volumes\":[",
                "\"mounts/compact:C:\\\\Mounted\\\\Compact\",",
                "{{",
                "\"host_path\":\"mounts/object\",",
                "\"guest_path\":\"D:/Mounted/Object\",",
                "\"recursive\":false",
                "}}",
                "]",
                "}}"
            ),
            sample.path.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();

    assert_eq!(config.volumes.len(), 2);
    assert_eq!(config.volumes[0].host_path, compact_host);
    assert_eq!(config.volumes[0].guest_path, r"C:\Mounted\Compact");
    assert!(config.volumes[0].recursive);
    assert_eq!(config.volumes[1].host_path, object_host);
    assert_eq!(config.volumes[1].guest_path, r"D:\Mounted\Object");
    assert!(!config.volumes[1].recursive);

    fs::remove_file(config_path).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn load_config_parses_environment_overrides_and_auto_mount_flag() {
    let sample = runtime_sample();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-env-overrides-config-{timestamp}.json"
    ));

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"auto_mount_module_dirs\":false,",
                "\"environment_overrides\":{{",
                "\"machine\":{{",
                "\"computer_name\":\"CFGBOX\",",
                "\"current_directory\":\"C:\\\\Lab\\\\Drop\"",
                "}},",
                "\"shell_folders\":{{",
                "\"profile\":\"C:\\\\Users\\\\cfg\",",
                "\"app_data\":\"C:\\\\Users\\\\cfg\\\\AppData\\\\Roaming\"",
                "}},",
                "\"os_version\":{{",
                "\"build\":22631,",
                "\"product_name\":\"Windows 11 Enterprise\"",
                "}},",
                "\"volume\":{{",
                "\"drive_type\":3,",
                "\"total_bytes\":4294967296",
                "}},",
                "\"environment_variables\":[",
                "{{\"name\":\"APPDATA\",\"value\":\"C:\\\\Users\\\\cfg\\\\AppData\\\\Roaming\"}}",
                "]",
                "}}",
                "}}"
            ),
            sample.path.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();
    let overrides = config.environment_overrides.as_ref().unwrap();

    assert!(!config.auto_mount_module_dirs);
    assert_eq!(
        overrides
            .machine
            .as_ref()
            .and_then(|machine| machine.computer_name.as_deref()),
        Some("CFGBOX")
    );
    assert_eq!(
        overrides
            .machine
            .as_ref()
            .and_then(|machine| machine.current_directory.as_deref()),
        Some(r"C:\Lab\Drop")
    );
    assert_eq!(
        overrides
            .os_version
            .as_ref()
            .and_then(|version| version.build),
        Some(22631)
    );
    assert_eq!(
        overrides
            .shell_folders
            .as_ref()
            .and_then(|folders| folders.profile.as_deref()),
        Some(r"C:\Users\cfg")
    );
    assert_eq!(
        overrides
            .volume
            .as_ref()
            .and_then(|volume| volume.total_bytes),
        Some(4_294_967_296)
    );
    assert_eq!(
        overrides.environment_variables.as_ref().unwrap()[0].name,
        "APPDATA"
    );

    fs::remove_file(config_path).unwrap();
}

#[test]
fn load_config_parses_module_policy_from_nested_modules_block() {
    let sample = runtime_sample();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-module-policy-config-{timestamp}"
    ));
    let config_dir = root.join("configs");
    let decoy_x86 = root.join("decoys").join("x86");
    let decoy_x64 = root.join("decoys").join("x64");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&decoy_x86).unwrap();
    fs::create_dir_all(&decoy_x64).unwrap();

    let config_path = config_dir.join("sample.json");
    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"modules\":{{",
                "\"modules_always_exist\":false,",
                "\"functions_always_exist\":false,",
                "\"module_directory_x86\":\"decoys/x86\",",
                "\"module_directory_x64\":\"decoys/x64\"",
                "}}",
                "}}"
            ),
            sample.path.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();

    assert!(!config.modules_always_exist);
    assert!(!config.functions_always_exist);
    assert_eq!(config.module_directory_x86.as_ref(), Some(&decoy_x86));
    assert_eq!(config.module_directory_x64.as_ref(), Some(&decoy_x64));
    assert_eq!(
        config.module_resolution_paths_for_arch("x86").last(),
        Some(&decoy_x86)
    );
    assert_eq!(
        config.module_resolution_paths_for_arch("x64").last(),
        Some(&decoy_x64)
    );

    fs::remove_file(config_path).unwrap();
    fs::remove_dir_all(root).unwrap();
}
