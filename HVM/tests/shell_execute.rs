use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;
use hvm::tests_support::build_loaded_engine;

#[test]
fn shell_execute_hook_records_live_child_process() {
    let mut engine = build_loaded_engine();

    assert_eq!(
        engine.shell32().shell_execute_w_for_test(
            r"C:\Windows\System32\cmd.exe",
            Some("/c echo shell"),
            Some(r"C:\Sandbox\ShellExec"),
        ),
        Some(33)
    );

    let process = engine.processes().latest_process().unwrap();

    assert!(process.command_line.ends_with("cmd.exe /c echo shell"));
    assert_eq!(process.current_directory, r"C:\Sandbox\ShellExec");
}

#[test]
fn is_user_an_admin_hook_reports_default_admin_profile() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("shell32.dll", "IsUserAnAdmin");
    assert_eq!(engine.dispatch_bound_stub(stub, &[]).unwrap(), 1);
}

#[test]
fn shell_execute_ex_hook_returns_process_handle_when_requested() {
    let mut engine = build_loaded_engine();
    let handle = engine
        .shell32()
        .shell_execute_ex_w_for_test(
            r"C:\Windows\System32\notepad.exe",
            Some("test.txt"),
            None,
            true,
        )
        .unwrap();

    let process = engine.processes().find_process_by_handle(handle).unwrap();

    assert!(handle != 0);
    assert!(process.command_line.ends_with("notepad.exe test.txt"));
}

#[test]
fn shell_execute_ex_hook_dispatches_through_runtime_stub() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let base = engine.allocate_executable_test_page(0x6200_0000).unwrap();
    let info = base;
    let file_ptr = base + 0x100;
    let params_ptr = base + 0x180;
    let dir_ptr = base + 0x240;

    write_wide(&mut engine, file_ptr, r"C:\Windows\System32\notepad.exe");
    write_wide(&mut engine, params_ptr, "runtime.txt");
    write_wide(&mut engine, dir_ptr, r"C:\Sandbox\RuntimeShell");

    let mut payload = vec![0u8; 0x40];
    payload[0x04..0x08].copy_from_slice(&0x40u32.to_le_bytes());
    payload[0x10..0x14].copy_from_slice(&(file_ptr as u32).to_le_bytes());
    payload[0x14..0x18].copy_from_slice(&(params_ptr as u32).to_le_bytes());
    payload[0x18..0x1C].copy_from_slice(&(dir_ptr as u32).to_le_bytes());
    engine.write_test_bytes(info, &payload).unwrap();

    let stub = engine.bind_hook_for_test("shell32.dll", "ShellExecuteExW");
    let retval = engine.call_native_for_test(stub, &[info]).unwrap();
    let handle = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(info + 0x38, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let process = engine.processes().find_process_by_handle(handle).unwrap();

    assert_eq!(retval, 1);
    assert!(handle != 0);
    assert!(process.command_line.ends_with("notepad.exe runtime.txt"));
    assert_eq!(process.current_directory, r"C:\Sandbox\RuntimeShell");
}

#[test]
fn shell_execute_ex_hook_intercepts_relative_call_stub() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let base = engine.allocate_executable_test_page(0x6210_0000).unwrap();
    let info = base;
    let file_ptr = base + 0x100;
    let params_ptr = base + 0x180;
    let dir_ptr = base + 0x240;
    let code = base + 0x300;

    write_wide(&mut engine, file_ptr, r"C:\Windows\System32\cmd.exe");
    write_wide(&mut engine, params_ptr, "/c echo runtime");
    write_wide(&mut engine, dir_ptr, r"C:\Sandbox\RuntimeCall");

    let mut payload = vec![0u8; 0x40];
    payload[0x04..0x08].copy_from_slice(&0x40u32.to_le_bytes());
    payload[0x10..0x14].copy_from_slice(&(file_ptr as u32).to_le_bytes());
    payload[0x14..0x18].copy_from_slice(&(params_ptr as u32).to_le_bytes());
    payload[0x18..0x1C].copy_from_slice(&(dir_ptr as u32).to_le_bytes());
    engine.write_test_bytes(info, &payload).unwrap();

    let stub = engine.bind_hook_for_test("shell32.dll", "ShellExecuteExW");
    let next_after_call = code + 10;
    let rel = (stub as i64 - next_after_call as i64) as i32;
    let mut bytes = vec![0x68];
    bytes.extend_from_slice(&(info as u32).to_le_bytes());
    bytes.push(0xE8);
    bytes.extend_from_slice(&rel.to_le_bytes());
    bytes.push(0xC3);
    engine.write_test_bytes(code, &bytes).unwrap();

    let retval = engine.call_native_for_test(code, &[]).unwrap();
    let handle = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(info + 0x38, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let process = engine.processes().find_process_by_handle(handle).unwrap();

    assert_eq!(retval, 1);
    assert!(handle != 0);
    assert!(process.command_line.ends_with("cmd.exe /c echo runtime"));
    assert_eq!(process.current_directory, r"C:\Sandbox\RuntimeCall");
}

#[test]
fn shell_execute_child_handle_exposes_remote_process_runtime_state() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let base = engine.allocate_executable_test_page(0x6220_0000).unwrap();
    let info = base;
    let file_ptr = base + 0x100;
    let params_ptr = base + 0x180;
    let dir_ptr = base + 0x240;
    let basic = base + 0x400;
    let basic_len = base + 0x500;
    let file_name_buffer = base + 0x600;

    write_wide(&mut engine, file_ptr, r"C:\Windows\System32\notepad.exe");
    write_wide(&mut engine, params_ptr, "remote.txt");
    write_wide(&mut engine, dir_ptr, r"C:\Sandbox\ShellExec");

    let mut payload = vec![0u8; 0x40];
    payload[0x04..0x08].copy_from_slice(&0x40u32.to_le_bytes());
    payload[0x10..0x14].copy_from_slice(&(file_ptr as u32).to_le_bytes());
    payload[0x14..0x18].copy_from_slice(&(params_ptr as u32).to_le_bytes());
    payload[0x18..0x1C].copy_from_slice(&(dir_ptr as u32).to_le_bytes());
    engine.write_test_bytes(info, &payload).unwrap();

    let shell_execute = engine.bind_hook_for_test("shell32.dll", "ShellExecuteExW");
    let get_module_file_name = engine.bind_hook_for_test("kernel32.dll", "K32GetModuleFileNameExW");
    let nt_query = engine.bind_hook_for_test("ntdll.dll", "NtQueryInformationProcess");

    assert_eq!(
        engine.call_native_for_test(shell_execute, &[info]).unwrap(),
        1
    );
    let handle = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(info + 0x38, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    ) as u64;
    assert_ne!(handle, 0);

    let pointer_size = runtime_pointer_size(&engine);
    let basic_size = if pointer_size == 8 { 48 } else { 24 };
    assert_eq!(
        engine
            .call_native_for_test(nt_query, &[handle, 0, basic, basic_size as u64, basic_len])
            .unwrap(),
        0
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(basic_len, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as usize,
        basic_size
    );
    assert_ne!(
        read_runtime_pointer(&engine, basic + if pointer_size == 8 { 8 } else { 4 }),
        0
    );

    assert!(
        engine
            .dispatch_bound_stub(get_module_file_name, &[handle, 0, file_name_buffer, 260])
            .unwrap()
            > 0
    );
    assert!(read_wide_c_string(&engine, file_name_buffer, 260)
        .to_ascii_lowercase()
        .ends_with("notepad.exe"));
}

fn read_wide_c_string(engine: &VirtualExecutionEngine, address: u64, capacity: usize) -> String {
    let bytes = engine
        .modules()
        .memory()
        .read(address, capacity.saturating_mul(2))
        .unwrap();
    let mut words = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            break;
        }
        words.push(word);
    }
    String::from_utf16_lossy(&words)
}

fn runtime_pointer_size(engine: &VirtualExecutionEngine) -> usize {
    if engine
        .entry_module()
        .or_else(|| engine.main_module())
        .map(|module| module.arch.eq_ignore_ascii_case("x64"))
        .unwrap_or(false)
    {
        8
    } else {
        4
    }
}

fn read_runtime_pointer(engine: &VirtualExecutionEngine, address: u64) -> u64 {
    let pointer_size = runtime_pointer_size(engine);
    let bytes = engine
        .modules()
        .memory()
        .read(address, pointer_size)
        .unwrap();
    if pointer_size == 8 {
        u64::from_le_bytes(bytes.try_into().unwrap())
    } else {
        u32::from_le_bytes(bytes.try_into().unwrap()) as u64
    }
}

fn write_wide(engine: &mut VirtualExecutionEngine, address: u64, text: &str) {
    let encoded = text
        .encode_utf16()
        .flat_map(|word| word.to_le_bytes())
        .chain([0, 0])
        .collect::<Vec<_>>();
    engine.write_test_bytes(address, &encoded).unwrap();
}
