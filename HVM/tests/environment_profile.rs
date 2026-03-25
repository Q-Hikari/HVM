use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::load_config;
use hvm::environment_profile::{
    EnvironmentOverrides, EnvironmentVariableProfile, MachineIdentityOverrides,
};
use hvm::managers::registry_manager::HKEY_LOCAL_MACHINE;
use hvm::runtime::engine::VirtualExecutionEngine;

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

fn unique_root(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-{test_name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn write_profile(root: &PathBuf) -> PathBuf {
    let path = root.join("environment_profile.json");
    fs::write(
        &path,
        r#"{
  "machine": {
    "computer_name": "WINLAB-42",
    "user_name": "analyst",
    "machine_guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff",
    "process_id": 16962,
    "image_path": "C:\\70e4c487e946a5f80be59f65e9e24372.exe",
    "parent_process_id": 20817,
    "parent_image_path": "C:\\Windows\\explorer.exe",
    "parent_command_line": "C:\\Windows\\explorer.exe",
    "system_root": "C:\\Windows",
    "system32": "C:\\Windows\\System32",
    "temp_dir": "C:\\Lab\\Temp",
    "current_directory": "C:\\Lab\\Workspace",
    "command_line": "C:\\70e4c487e946a5f80be59f65e9e24372.exe"
  },
  "os_version": {
    "major": 10,
    "minor": 0,
    "build": 22621,
    "platform_id": 2,
    "product_type": 1,
    "product_name": "Windows 11 Pro",
    "product_id": "00331-10000-00001-AA123"
  },
  "locale": {
    "acp": 936,
    "oemcp": 437,
    "console_cp": 65001,
    "console_output_cp": 65001,
    "user_default_lcid": 2052,
    "thread_locale": 1033,
    "system_default_ui_language": 1033,
    "user_default_ui_language": 2052
  },
  "display": {
    "desktop_window_handle": 1048576,
    "active_window_handle": 1048592,
    "shell_window_handle": 1048608,
    "screen_width": 1600,
    "screen_height": 900,
    "cursor_x": 317,
    "cursor_y": 31,
    "message_x": 317,
    "message_y": 31,
    "message_step_x": 0,
    "message_step_y": 0,
    "remote_session": false
  },
  "volume": {
    "root_path": "C:\\\\",
    "volume_name": "WorkDisk",
    "serial": 287454020,
    "max_component_length": 255,
    "flags": 459007,
    "fs_name": "NTFS",
    "drive_type": 3,
    "total_bytes": 4294967296,
    "free_bytes": 2147483648,
    "available_bytes": 1610612736,
    "volume_guid": "\\\\?\\Volume{11223344-5566-7788-99aa-bbccddeeff00}\\"
  },
  "shell_folders": {
    "profile": "C:\\Users\\analyst",
    "desktop": "C:\\Users\\analyst\\Desktop",
    "app_data": "C:\\Users\\analyst\\AppData\\Roaming",
    "local_app_data": "C:\\Users\\analyst\\AppData\\Local",
    "program_data": "C:\\ProgramData",
    "startup": "C:\\Users\\analyst\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "personal": "C:\\Users\\analyst\\Documents",
    "public": "C:\\Users\\Public"
  },
  "environment_variables": [
    {
      "name": "APPDATA",
      "value": "C:\\Users\\analyst\\AppData\\Roaming"
    },
    {
      "name": "COMSPEC",
      "value": "C:\\Windows\\System32\\cmd.exe"
    }
  ],
  "processes": [
    {
      "pid": 2800,
      "parent_pid": 620,
      "image_path": "C:\\Windows\\System32\\svchost.exe",
      "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
      "current_directory": "C:\\Windows\\System32"
    },
    {
      "pid": 3540,
      "parent_pid": 2800,
      "image_path": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
      "command_line": "\"C:\\Program Files\\Windows Defender\\MsMpEng.exe\"",
      "current_directory": "C:\\Program Files\\Windows Defender"
    }
  ],
  "registry": {
    "keys": [
      {
        "path": "HKEY_LOCAL_MACHINE\\Software\\SnapshotProfile",
        "values": [
          {
            "name": "Marker",
            "value_type": 1,
            "string": "present"
          }
        ]
      }
    ]
  }
}"#,
    )
    .unwrap();
    path
}

fn alloc_page(engine: &mut VirtualExecutionEngine, preferred: u64) -> u64 {
    let address = engine.allocate_executable_test_page(preferred).unwrap();
    engine.write_test_bytes(address, &[0u8; 0x1000]).unwrap();
    address
}

fn write_u32(engine: &mut VirtualExecutionEngine, address: u64, value: u32) {
    engine
        .write_test_bytes(address, &value.to_le_bytes())
        .unwrap();
}

fn write_wide(engine: &mut VirtualExecutionEngine, address: u64, value: &str) {
    let mut bytes = value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    bytes.extend_from_slice(&[0, 0]);
    engine.write_test_bytes(address, &bytes).unwrap();
}

fn read_u32(engine: &VirtualExecutionEngine, address: u64) -> u32 {
    u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(address, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn read_u64(engine: &VirtualExecutionEngine, address: u64) -> u64 {
    u64::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(address, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn read_c_string(engine: &VirtualExecutionEngine, address: u64, capacity: usize) -> String {
    let bytes = engine.modules().memory().read(address, capacity).unwrap();
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn read_wide_string(engine: &VirtualExecutionEngine, address: u64, words: usize) -> String {
    let bytes = engine.modules().memory().read(address, words * 2).unwrap();
    let mut data = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            break;
        }
        data.push(word);
    }
    String::from_utf16_lossy(&data)
}

fn read_wide_multi_sz(engine: &VirtualExecutionEngine, address: u64, words: usize) -> Vec<String> {
    let bytes = engine.modules().memory().read(address, words * 2).unwrap();
    let mut current = Vec::new();
    let mut entries = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            if current.is_empty() {
                break;
            }
            entries.push(String::from_utf16_lossy(&current));
            current.clear();
            continue;
        }
        current.push(word);
    }
    entries
}

fn read_wide_process_entry(
    engine: &VirtualExecutionEngine,
    address: u64,
) -> (u32, u32, u32, String) {
    let pid = read_u32(engine, address + 8);
    let thread_count = read_u32(engine, address + 20);
    let parent_pid = read_u32(engine, address + 24);
    let image_name = read_wide_string(engine, address + 36, 260);
    (pid, parent_pid, thread_count, image_name)
}

#[test]
fn environment_profile_overrides_identity_gui_and_volume_hooks() {
    let root = unique_root("environment-profile-hooks");
    let profile_path = write_profile(&root);
    let mut config = sample_config();
    config.environment_profile = Some(profile_path);

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let get_computer = engine.bind_hook_for_test("kernel32.dll", "GetComputerNameW");
    let get_user = engine.bind_hook_for_test("advapi32.dll", "GetUserNameA");
    let get_pid = engine.bind_hook_for_test("kernel32.dll", "GetCurrentProcessId");
    let get_desktop = engine.bind_hook_for_test("user32.dll", "GetDesktopWindow");
    let get_message_pos = engine.bind_hook_for_test("user32.dll", "GetMessagePos");
    let get_volume = engine.bind_hook_for_test("kernel32.dll", "GetVolumeInformationA");
    let get_temp = engine.bind_hook_for_test("kernel32.dll", "GetTempPathW");
    let get_console_cp = engine.bind_hook_for_test("kernel32.dll", "GetConsoleCP");
    let get_command_line = engine.bind_hook_for_test("kernel32.dll", "GetCommandLineW");
    let query_image_name = engine.bind_hook_for_test("kernel32.dll", "QueryFullProcessImageNameW");

    let name_buffer = alloc_page(&mut engine, 0x7100_0000);
    let size_ptr = name_buffer + 0x100;
    write_u32(&mut engine, size_ptr, 64);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_computer, &[name_buffer, size_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_wide_string(&engine, name_buffer, 64), "WINLAB-42");
    assert_eq!(read_u32(&engine, size_ptr), 9);

    let user_buffer = alloc_page(&mut engine, 0x7100_2000);
    let user_size_ptr = user_buffer + 0x100;
    write_u32(&mut engine, user_size_ptr, 64);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_user, &[user_buffer, user_size_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_c_string(&engine, user_buffer, 64), "analyst");
    assert_eq!(read_u32(&engine, user_size_ptr), 8);

    assert_eq!(engine.dispatch_bound_stub(get_pid, &[]).unwrap(), 0x4242);
    assert_eq!(
        engine.dispatch_bound_stub(get_desktop, &[]).unwrap(),
        0x0010_0000
    );
    assert_eq!(
        engine.dispatch_bound_stub(get_message_pos, &[]).unwrap(),
        0x001F_013D
    );
    assert_eq!(
        engine.dispatch_bound_stub(get_console_cp, &[]).unwrap(),
        65001
    );

    let volume_name = alloc_page(&mut engine, 0x7100_4000);
    let fs_name = alloc_page(&mut engine, 0x7100_5000);
    let serial_ptr = volume_name + 0x100;
    let max_len_ptr = volume_name + 0x104;
    let flags_ptr = volume_name + 0x108;
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_volume,
                &[
                    0,
                    volume_name,
                    64,
                    serial_ptr,
                    max_len_ptr,
                    flags_ptr,
                    fs_name,
                    32
                ],
            )
            .unwrap(),
        1
    );
    assert_eq!(read_c_string(&engine, volume_name, 64), "WorkDisk");
    assert_eq!(read_c_string(&engine, fs_name, 32), "NTFS");
    assert_eq!(read_u32(&engine, serial_ptr), 0x1122_3344);
    assert_eq!(read_u32(&engine, max_len_ptr), 255);
    assert_eq!(read_u32(&engine, flags_ptr), 0x0007_00FF);

    let temp_buffer = alloc_page(&mut engine, 0x7100_6000);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_temp, &[64, temp_buffer])
            .unwrap(),
        12
    );
    assert_eq!(
        read_wide_string(&engine, temp_buffer, 64),
        "C:\\Lab\\Temp\\"
    );
    assert_eq!(
        engine.current_directory(),
        std::path::Path::new("C:\\Lab\\Workspace")
    );
    assert_eq!(
        engine.command_line(),
        "C:\\70e4c487e946a5f80be59f65e9e24372.exe"
    );
    let command_line_ptr = engine.dispatch_bound_stub(get_command_line, &[]).unwrap();
    assert_eq!(
        read_wide_string(&engine, command_line_ptr, 96),
        "C:\\70e4c487e946a5f80be59f65e9e24372.exe"
    );
    let image_buffer = alloc_page(&mut engine, 0x7100_7000);
    let image_len = image_buffer + 0x200;
    write_u32(&mut engine, image_len, 128);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_image_name,
                &[u32::MAX as u64, 0, image_buffer, image_len]
            )
            .unwrap(),
        1
    );
    assert_eq!(
        read_wide_string(&engine, image_buffer, 128),
        "C:\\70e4c487e946a5f80be59f65e9e24372.exe"
    );
}

#[test]
fn config_environment_overrides_merge_on_top_of_environment_profile() {
    let root = unique_root("environment-profile-config-overrides");
    let profile_path = write_profile(&root);
    let mut config = sample_config();
    config.environment_profile = Some(profile_path);
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            computer_name: Some("CFGBOX".to_string()),
            user_name: Some("cfguser".to_string()),
            image_path: Some(r"C:\Cfg\Drop\dropper.exe".to_string()),
            temp_dir: Some(r"C:\Cfg\Temp".to_string()),
            current_directory: Some(r"C:\Cfg\Drop".to_string()),
            command_line: Some(r"C:\Cfg\Drop\dropper.exe /cfg".to_string()),
            ..Default::default()
        }),
        environment_variables: Some(vec![EnvironmentVariableProfile {
            name: "APPDATA".to_string(),
            value: r"C:\Users\cfguser\AppData\Roaming".to_string(),
        }]),
        ..Default::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let get_computer = engine.bind_hook_for_test("kernel32.dll", "GetComputerNameW");
    let get_user = engine.bind_hook_for_test("advapi32.dll", "GetUserNameA");
    let get_temp = engine.bind_hook_for_test("kernel32.dll", "GetTempPathW");
    let get_command_line = engine.bind_hook_for_test("kernel32.dll", "GetCommandLineW");
    let get_env = engine.bind_hook_for_test("kernel32.dll", "GetEnvironmentVariableW");

    let name_buffer = alloc_page(&mut engine, 0x7101_0000);
    let name_size = name_buffer + 0x100;
    write_u32(&mut engine, name_size, 64);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_computer, &[name_buffer, name_size])
            .unwrap(),
        1
    );
    assert_eq!(read_wide_string(&engine, name_buffer, 64), "CFGBOX");

    let user_buffer = alloc_page(&mut engine, 0x7101_2000);
    let user_size = user_buffer + 0x100;
    write_u32(&mut engine, user_size, 64);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_user, &[user_buffer, user_size])
            .unwrap(),
        1
    );
    assert_eq!(read_c_string(&engine, user_buffer, 64), "cfguser");

    let temp_buffer = alloc_page(&mut engine, 0x7101_4000);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_temp, &[64, temp_buffer])
            .unwrap(),
        12
    );
    assert_eq!(
        read_wide_string(&engine, temp_buffer, 64),
        "C:\\Cfg\\Temp\\"
    );
    assert_eq!(
        engine.current_directory(),
        std::path::Path::new("C:\\Cfg\\Drop")
    );
    assert_eq!(engine.command_line(), "C:\\Cfg\\Drop\\dropper.exe /cfg");

    let env_name = alloc_page(&mut engine, 0x7101_6000);
    let env_value = alloc_page(&mut engine, 0x7101_7000);
    write_wide(&mut engine, env_name, "APPDATA");
    assert_eq!(
        engine
            .dispatch_bound_stub(get_env, &[env_name, env_value, 128])
            .unwrap(),
        r"C:\Users\cfguser\AppData\Roaming".encode_utf16().count() as u64
    );
    assert_eq!(
        read_wide_string(&engine, env_value, 128),
        r"C:\Users\cfguser\AppData\Roaming"
    );

    let command_line_ptr = engine.dispatch_bound_stub(get_command_line, &[]).unwrap();
    assert_eq!(
        read_wide_string(&engine, command_line_ptr, 96),
        "C:\\Cfg\\Drop\\dropper.exe /cfg"
    );
}

#[test]
fn environment_profile_seeds_registry_snapshot_and_version_info() {
    let root = unique_root("environment-profile-registry");
    let profile_path = write_profile(&root);
    let mut config = sample_config();
    config.environment_profile = Some(profile_path);

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let reg_open = engine.bind_hook_for_test("advapi32.dll", "RegOpenKeyExW");
    let reg_query = engine.bind_hook_for_test("advapi32.dll", "RegQueryValueExW");
    let get_version = engine.bind_hook_for_test("kernel32.dll", "GetVersionExW");

    let key_path = alloc_page(&mut engine, 0x7200_0000);
    let value_name = alloc_page(&mut engine, 0x7200_1000);
    let handle_ptr = key_path + 0x200;
    write_wide(&mut engine, key_path, "Software\\SnapshotProfile");
    write_wide(&mut engine, value_name, "Marker");
    assert_eq!(
        engine
            .dispatch_bound_stub(
                reg_open,
                &[HKEY_LOCAL_MACHINE as u64, key_path, 0, 0, handle_ptr],
            )
            .unwrap(),
        0
    );
    let key_handle = read_u32(&engine, handle_ptr) as u64;
    assert_ne!(key_handle, 0);

    let data_buffer = alloc_page(&mut engine, 0x7200_2000);
    let type_ptr = data_buffer + 0x100;
    let size_ptr = data_buffer + 0x104;
    write_u32(&mut engine, size_ptr, 64);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                reg_query,
                &[key_handle, value_name, 0, type_ptr, data_buffer, size_ptr]
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, type_ptr), 1);
    assert_eq!(read_wide_string(&engine, data_buffer, 64), "present");

    write_wide(
        &mut engine,
        key_path,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
    );
    write_wide(&mut engine, value_name, "ProductId");
    assert_eq!(
        engine
            .dispatch_bound_stub(
                reg_open,
                &[HKEY_LOCAL_MACHINE as u64, key_path, 0, 0, handle_ptr],
            )
            .unwrap(),
        0
    );
    let current_version_handle = read_u32(&engine, handle_ptr) as u64;
    write_u32(&mut engine, size_ptr, 64);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                reg_query,
                &[
                    current_version_handle,
                    value_name,
                    0,
                    type_ptr,
                    data_buffer,
                    size_ptr
                ]
            )
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, data_buffer, 64),
        "00331-10000-00001-AA123"
    );

    write_wide(&mut engine, key_path, "SOFTWARE\\Microsoft\\Cryptography");
    write_wide(&mut engine, value_name, "MachineGuid");
    assert_eq!(
        engine
            .dispatch_bound_stub(
                reg_open,
                &[HKEY_LOCAL_MACHINE as u64, key_path, 0, 0, handle_ptr],
            )
            .unwrap(),
        0
    );
    let cryptography_handle = read_u32(&engine, handle_ptr) as u64;
    write_u32(&mut engine, size_ptr, 96);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                reg_query,
                &[
                    cryptography_handle,
                    value_name,
                    0,
                    type_ptr,
                    data_buffer,
                    size_ptr
                ]
            )
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, data_buffer, 96),
        "6f9619ff-8b86-d011-b42d-00c04fc964ff"
    );

    let version_info = alloc_page(&mut engine, 0x7200_3000);
    write_u32(&mut engine, version_info, 0x11C);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_version, &[version_info])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, version_info + 4), 10);
    assert_eq!(read_u32(&engine, version_info + 8), 0);
    assert_eq!(read_u32(&engine, version_info + 12), 22621);
}

#[test]
fn default_user32_message_position_advances_between_calls() {
    let config = sample_config();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let get_message_pos = engine.bind_hook_for_test("user32.dll", "GetMessagePos");
    let first = engine.dispatch_bound_stub(get_message_pos, &[]).unwrap();
    let second = engine.dispatch_bound_stub(get_message_pos, &[]).unwrap();
    let third = engine.dispatch_bound_stub(get_message_pos, &[]).unwrap();

    assert_ne!(first, second);
    assert_ne!(second, third);
}

#[test]
fn environment_profile_exposes_custom_environment_variables_and_process_inventory() {
    let root = unique_root("environment-profile-env-processes");
    let profile_path = write_profile(&root);
    let mut config = sample_config();
    config.environment_profile = Some(profile_path);

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let get_env = engine.bind_hook_for_test("kernel32.dll", "GetEnvironmentVariableW");
    let expand_env = engine.bind_hook_for_test("kernel32.dll", "ExpandEnvironmentStringsW");
    let create_snapshot = engine.bind_hook_for_test("kernel32.dll", "CreateToolhelp32Snapshot");
    let process32_first = engine.bind_hook_for_test("kernel32.dll", "Process32FirstW");
    let process32_next = engine.bind_hook_for_test("kernel32.dll", "Process32NextW");

    let name_ptr = alloc_page(&mut engine, 0x7300_0000);
    let value_ptr = alloc_page(&mut engine, 0x7300_1000);
    write_wide(&mut engine, name_ptr, "APPDATA");
    let env_value = "C:\\Users\\analyst\\AppData\\Roaming";
    let returned = engine
        .dispatch_bound_stub(get_env, &[name_ptr, value_ptr, 128])
        .unwrap();
    let observed_value = read_wide_string(&engine, value_ptr, 128);
    assert_eq!(observed_value, env_value);
    assert_eq!(returned, observed_value.encode_utf16().count() as u64);

    let expand_source = alloc_page(&mut engine, 0x7300_2000);
    let expand_target = alloc_page(&mut engine, 0x7300_3000);
    write_wide(
        &mut engine,
        expand_source,
        "%APPDATA%|%COMSPEC%|%CD%|%SystemRoot%|%USERPROFILE%|%LOCALAPPDATA%|%ProgramData%|%USERNAME%|%COMPUTERNAME%",
    );
    let expanded_len = engine
        .dispatch_bound_stub(expand_env, &[expand_source, expand_target, 256])
        .unwrap();
    assert!(expanded_len > 0);
    assert_eq!(
        read_wide_string(&engine, expand_target, 256),
        "C:\\Users\\analyst\\AppData\\Roaming|C:\\Windows\\System32\\cmd.exe|C:\\Lab\\Workspace|C:\\Windows|C:\\Users\\analyst|C:\\Users\\analyst\\AppData\\Local|C:\\ProgramData|analyst|WINLAB-42"
    );

    let snapshot = engine
        .dispatch_bound_stub(create_snapshot, &[0x0000_0002, 0])
        .unwrap();
    assert_ne!(snapshot, u32::MAX as u64);

    let entry = alloc_page(&mut engine, 0x7300_4000);
    let mut entry_seed = vec![0u8; 556];
    entry_seed[0..4].copy_from_slice(&556u32.to_le_bytes());
    engine.write_test_bytes(entry, &entry_seed).unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(process32_first, &[snapshot, entry])
            .unwrap(),
        1
    );
    let mut entries = vec![read_wide_process_entry(&engine, entry)];
    loop {
        let result = engine
            .dispatch_bound_stub(process32_next, &[snapshot, entry])
            .unwrap();
        if result == 0 {
            break;
        }
        entries.push(read_wide_process_entry(&engine, entry));
    }

    assert!(
        entries.iter().any(|(pid, ppid, _, image_name)| {
            *pid == 2800 && *ppid == 620 && image_name.eq_ignore_ascii_case("svchost.exe")
        }),
        "{entries:#?}"
    );
    assert!(
        entries.iter().any(|(pid, ppid, _, image_name)| {
            *pid == 3540 && *ppid == 2800 && image_name.eq_ignore_ascii_case("MsMpEng.exe")
        }),
        "{entries:#?}"
    );
}

#[test]
fn environment_profile_exposes_shell_folder_and_volume_probes() {
    let root = unique_root("environment-profile-shell-volume");
    let profile_path = write_profile(&root);
    let mut config = sample_config();
    config.environment_profile = Some(profile_path);

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let get_folder = engine.bind_hook_for_test("shell32.dll", "SHGetFolderPathW");
    let get_special = engine.bind_hook_for_test("shell32.dll", "SHGetSpecialFolderLocation");
    let get_path_from_id_list = engine.bind_hook_for_test("shell32.dll", "SHGetPathFromIDListW");
    let get_drive_strings = engine.bind_hook_for_test("kernel32.dll", "GetLogicalDriveStringsW");
    let get_drive_type = engine.bind_hook_for_test("kernel32.dll", "GetDriveTypeW");
    let get_disk_space = engine.bind_hook_for_test("kernel32.dll", "GetDiskFreeSpaceExW");
    let find_first_volume = engine.bind_hook_for_test("kernel32.dll", "FindFirstVolumeW");
    let find_volume_close = engine.bind_hook_for_test("kernel32.dll", "FindVolumeClose");

    let folder_buffer = alloc_page(&mut engine, 0x7400_0000);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_folder, &[0, 0x001A, 0, 0, folder_buffer])
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, folder_buffer, 128),
        r"C:\Users\analyst\AppData\Roaming"
    );

    let pidl_out = alloc_page(&mut engine, 0x7400_1000);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_special, &[0, 0x0028, pidl_out])
            .unwrap(),
        0
    );
    let pidl = read_u32(&engine, pidl_out) as u64;
    assert_ne!(pidl, 0);

    let path_buffer = alloc_page(&mut engine, 0x7400_2000);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_path_from_id_list, &[pidl, path_buffer])
            .unwrap(),
        1
    );
    assert_eq!(
        read_wide_string(&engine, path_buffer, 128),
        r"C:\Users\analyst"
    );

    let drive_buffer = alloc_page(&mut engine, 0x7400_3000);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_drive_strings, &[32, drive_buffer])
            .unwrap(),
        4
    );
    assert_eq!(
        read_wide_multi_sz(&engine, drive_buffer, 16),
        vec![r"C:\".to_string()]
    );

    let root_path = alloc_page(&mut engine, 0x7400_4000);
    write_wide(&mut engine, root_path, r"C:\");
    assert_eq!(
        engine
            .dispatch_bound_stub(get_drive_type, &[root_path])
            .unwrap(),
        3
    );

    let available_ptr = alloc_page(&mut engine, 0x7400_5000);
    let total_ptr = alloc_page(&mut engine, 0x7400_6000);
    let free_ptr = alloc_page(&mut engine, 0x7400_7000);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_disk_space,
                &[root_path, available_ptr, total_ptr, free_ptr],
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u64(&engine, available_ptr), 1_610_612_736);
    assert_eq!(read_u64(&engine, total_ptr), 4_294_967_296);
    assert_eq!(read_u64(&engine, free_ptr), 2_147_483_648);

    let volume_buffer = alloc_page(&mut engine, 0x7400_8000);
    let volume_handle = engine
        .dispatch_bound_stub(find_first_volume, &[volume_buffer, 128])
        .unwrap();
    assert_ne!(volume_handle, 0);
    assert_eq!(
        read_wide_string(&engine, volume_buffer, 128),
        r"\\?\Volume{11223344-5566-7788-99aa-bbccddeeff00}\"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(find_volume_close, &[volume_handle])
            .unwrap(),
        1
    );
}
