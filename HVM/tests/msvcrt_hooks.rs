use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

fn sample_config_x64() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_42c4b1eaeba9de5a873970687b4abc34_trace.json");
    load_config(config_path).unwrap()
}

fn read_wide_c_string(engine: &VirtualExecutionEngine, address: u64, capacity: usize) -> String {
    let bytes = engine
        .modules()
        .memory()
        .read(address, capacity.saturating_mul(2))
        .unwrap();
    let words = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|word| *word != 0)
        .collect::<Vec<_>>();
    String::from_utf16(&words).unwrap()
}

fn write_wide_c_string(engine: &mut VirtualExecutionEngine, address: u64, value: &str) {
    let bytes = value
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    engine.write_test_bytes(address, &bytes).unwrap();
}

#[test]
fn msvcrt_calloc_zeroes_reused_heap_ranges() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let malloc = engine.bind_hook_for_test("msvcrt.dll", "malloc");
    let calloc = engine.bind_hook_for_test("msvcrt.dll", "calloc");
    let free = engine.bind_hook_for_test("msvcrt.dll", "free");

    let first = engine.dispatch_bound_stub(malloc, &[0x40]).unwrap();
    engine.write_test_bytes(first, &[0x41; 0x40]).unwrap();
    assert_eq!(engine.dispatch_bound_stub(free, &[first]).unwrap(), 0);

    let second = engine.dispatch_bound_stub(calloc, &[1, 0x40]).unwrap();
    assert_eq!(second, first);
    assert_eq!(
        engine.modules().memory().read(second, 0x40).unwrap(),
        vec![0u8; 0x40]
    );
}

#[test]
fn api_ms_crt_runtime_initialize_onexit_table_zeroes_pointer_triplet() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let table = engine.allocate_executable_test_page(0x6340_0000).unwrap();
    engine.write_test_bytes(table, &[0xAA; 0x20]).unwrap();

    let stub = engine.bind_hook_for_test(
        "api-ms-win-crt-runtime-l1-1-0.dll",
        "_initialize_onexit_table",
    );
    let retval = engine.dispatch_bound_stub(stub, &[table]).unwrap();
    let pointer_size = engine.modules().arch().pointer_size as u64;

    assert_eq!(retval, 0);
    assert_eq!(read_pointer(&engine, table).unwrap(), 0);
    assert_eq!(read_pointer(&engine, table + pointer_size).unwrap(), 0);
    assert_eq!(
        read_pointer(&engine, table + (pointer_size * 2)).unwrap(),
        0
    );
}

#[test]
fn api_ms_crt_runtime_initterm_e_invokes_callbacks_until_nonzero() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let initterm = engine.bind_hook_for_test("api-ms-win-crt-runtime-l1-1-0.dll", "_initterm_e");
    let callback = engine.bind_hook_for_test("kernel32.dll", "GetCurrentProcessId");
    let table = engine.allocate_executable_test_page(0x6341_0000).unwrap();
    let pointer_size = engine.modules().arch().pointer_size as usize;
    let mut payload = vec![0u8; pointer_size * 2];
    if pointer_size == 8 {
        payload[0..8].copy_from_slice(&callback.to_le_bytes());
    } else {
        payload[0..4].copy_from_slice(&(callback as u32).to_le_bytes());
    }
    engine.write_test_bytes(table, &payload).unwrap();

    let retval = engine
        .dispatch_bound_stub(initterm, &[table, table + pointer_size as u64])
        .unwrap();

    assert_eq!(retval, engine.dispatch_bound_stub(callback, &[]).unwrap());
}

#[test]
fn legacy_msvcr100_initterm_e_reuses_msvcrt_runtime_dispatch() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let initterm = engine.bind_hook_for_test("msvcr100.dll", "_initterm_e");
    let callback = engine.bind_hook_for_test("kernel32.dll", "GetCurrentProcessId");
    let table = engine.allocate_executable_test_page(0x6341_8000).unwrap();
    let pointer_size = engine.modules().arch().pointer_size as usize;
    let mut payload = vec![0u8; pointer_size * 2];
    if pointer_size == 8 {
        payload[0..8].copy_from_slice(&callback.to_le_bytes());
    } else {
        payload[0..4].copy_from_slice(&(callback as u32).to_le_bytes());
    }
    engine.write_test_bytes(table, &payload).unwrap();

    let retval = engine
        .dispatch_bound_stub(initterm, &[table, table + pointer_size as u64])
        .unwrap();

    assert_eq!(retval, engine.dispatch_bound_stub(callback, &[]).unwrap());
}

#[test]
fn msvcr120_crt_get_show_window_mode_returns_show_default() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("msvcr120.dll", "__crtGetShowWindowMode");
    assert_eq!(engine.dispatch_bound_stub(stub, &[]).unwrap(), 10);
}

#[test]
fn x64_active_unicorn_initterm_e_runs_native_callbacks_until_nonzero() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let initterm = engine.bind_hook_for_test("msvcrt.dll", "_initterm_e");
    let page = engine.allocate_executable_test_page(0x6342_0000).unwrap();
    let wrapper = page;
    let callback_zero = page + 0x100;
    let callback_value = page + 0x120;
    let table = page + 0x200;
    let end = table + 16;

    let mut wrapper_bytes = vec![0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9];
    wrapper_bytes.extend_from_slice(&table.to_le_bytes());
    wrapper_bytes.extend_from_slice(&[0x48, 0xBA]);
    wrapper_bytes.extend_from_slice(&end.to_le_bytes());
    wrapper_bytes.extend_from_slice(&[0x48, 0xB8]);
    wrapper_bytes.extend_from_slice(&initterm.to_le_bytes());
    wrapper_bytes.extend_from_slice(&[0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3]);

    let mut table_bytes = Vec::with_capacity(16);
    table_bytes.extend_from_slice(&callback_zero.to_le_bytes());
    table_bytes.extend_from_slice(&callback_value.to_le_bytes());

    engine.write_test_bytes(wrapper, &wrapper_bytes).unwrap();
    engine
        .write_test_bytes(callback_zero, &[0x31, 0xC0, 0xC3])
        .unwrap();
    engine
        .write_test_bytes(callback_value, &[0xB8, 0x42, 0x00, 0x00, 0x00, 0xC3])
        .unwrap();
    engine.write_test_bytes(table, &table_bytes).unwrap();

    assert_eq!(engine.call_native_for_test(wrapper, &[]).unwrap(), 0x42);
}

#[test]
fn x64_active_unicorn_initterm_e_preserves_caller_return_after_shadow_space_writes() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let initterm = engine.bind_hook_for_test("msvcrt.dll", "_initterm_e");
    let page = engine.allocate_executable_test_page(0x6343_0000).unwrap();
    let wrapper = page;
    let callback = page + 0x100;
    let table = page + 0x200;
    let end = table + 8;

    let mut wrapper_bytes = vec![0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9];
    wrapper_bytes.extend_from_slice(&table.to_le_bytes());
    wrapper_bytes.extend_from_slice(&[0x48, 0xBA]);
    wrapper_bytes.extend_from_slice(&end.to_le_bytes());
    wrapper_bytes.extend_from_slice(&[0x48, 0xB8]);
    wrapper_bytes.extend_from_slice(&initterm.to_le_bytes());
    wrapper_bytes.extend_from_slice(&[
        0xFF, 0xD0, 0xB8, 0x77, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xC3,
    ]);

    let mut table_bytes = Vec::with_capacity(8);
    table_bytes.extend_from_slice(&callback.to_le_bytes());

    engine.write_test_bytes(wrapper, &wrapper_bytes).unwrap();
    engine
        .write_test_bytes(
            callback,
            &[
                0x48, 0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3,
            ],
        )
        .unwrap();
    engine.write_test_bytes(table, &table_bytes).unwrap();

    assert_eq!(engine.call_native_for_test(wrapper, &[]).unwrap(), 0x77);
}

#[test]
fn api_ms_crt_runtime_seh_filter_dll_executes_handler_for_access_violation() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("api-ms-win-crt-runtime-l1-1-0.dll", "_seh_filter_dll");
    let page = engine.allocate_executable_test_page(0x6344_0000).unwrap();
    let exception_record = page + 0x100;
    let context_record = page + 0x200;
    let exception_pointers = page + 0x300;
    let pointer_size = engine.modules().arch().pointer_size as u64;

    engine
        .write_test_bytes(exception_record, &0xC000_0005u32.to_le_bytes())
        .unwrap();
    write_pointer(&mut engine, exception_pointers, exception_record).unwrap();
    write_pointer(
        &mut engine,
        exception_pointers + pointer_size,
        context_record,
    )
    .unwrap();

    let retval = engine
        .dispatch_bound_stub(stub, &[0xC000_0005, exception_pointers])
        .unwrap();

    assert_eq!(retval as u32 as i32, 1);
}

#[test]
fn api_ms_crt_runtime_seh_filter_dll_defers_cpp_exceptions_to_seh_filter_exe() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let dll = engine.bind_hook_for_test("api-ms-win-crt-runtime-l1-1-0.dll", "_seh_filter_dll");
    let exe = engine.bind_hook_for_test("api-ms-win-crt-runtime-l1-1-0.dll", "_seh_filter_exe");
    let page = engine.allocate_executable_test_page(0x6345_0000).unwrap();
    let exception_record = page + 0x100;
    let context_record = page + 0x200;
    let exception_pointers = page + 0x300;
    let pointer_size = engine.modules().arch().pointer_size as u64;

    engine
        .write_test_bytes(exception_record, &0xE06D_7363u32.to_le_bytes())
        .unwrap();
    write_pointer(&mut engine, exception_pointers, exception_record).unwrap();
    write_pointer(
        &mut engine,
        exception_pointers + pointer_size,
        context_record,
    )
    .unwrap();

    let dll_ret = engine
        .dispatch_bound_stub(dll, &[0xE06D_7363, exception_pointers])
        .unwrap();
    let exe_ret = engine
        .dispatch_bound_stub(exe, &[0xE06D_7363, exception_pointers])
        .unwrap();

    assert_eq!(dll_ret, exe_ret);
    assert_eq!(exe_ret as u32 as i32, 0);
}

#[test]
fn msvcrt_vsnwprintf_formats_decimal_arguments_into_wide_buffers() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let format_ptr = engine.allocate_executable_test_page(0x6346_0000).unwrap();
    let buffer_ptr = engine.allocate_executable_test_page(0x6346_1000).unwrap();
    let args_ptr = engine.allocate_executable_test_page(0x6346_2000).unwrap();
    engine
        .write_test_bytes(
            format_ptr,
            &"\\\\.\\PhysicalDrive%d"
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine.write_test_bytes(buffer_ptr, &[0u8; 128]).unwrap();
    engine
        .write_test_bytes(args_ptr, &7u32.to_le_bytes())
        .unwrap();

    let stub = engine.bind_hook_for_test("msvcrt.dll", "_vsnwprintf");
    let written = engine
        .dispatch_bound_stub(stub, &[buffer_ptr, 64, format_ptr, args_ptr])
        .unwrap();

    assert_eq!(written, r"\\.\PhysicalDrive7".encode_utf16().count() as u64);
    assert_eq!(
        read_wide_c_string(&engine, buffer_ptr, 64),
        r"\\.\PhysicalDrive7"
    );
}

#[test]
fn msvcrt_itow_s_formats_decimal_text_for_sample_hot_path() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("msvcrt.dll", "_itow_s");
    let buffer = engine.allocate_executable_test_page(0x6347_0000).unwrap();
    engine.write_test_bytes(buffer, &[0x41; 32]).unwrap();

    let retval = engine
        .dispatch_bound_stub(stub, &[1234, buffer, 6, 10])
        .unwrap();

    assert_eq!(retval, 0);
    assert_eq!(read_wide_c_string(&engine, buffer, 6), "1234");
}

#[test]
fn msvcrt_itow_s_clears_destination_when_capacity_is_too_small() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let itow_s = engine.bind_hook_for_test("msvcrt.dll", "_itow_s");
    let errno = engine.bind_hook_for_test("msvcrt.dll", "_errno");
    let buffer = engine.allocate_executable_test_page(0x6347_1000).unwrap();
    engine.write_test_bytes(buffer, &[0x42; 16]).unwrap();

    let retval = engine
        .dispatch_bound_stub(itow_s, &[123456, buffer, 4, 10])
        .unwrap();
    let errno_ptr = engine.dispatch_bound_stub(errno, &[]).unwrap();

    assert_eq!(retval, 34);
    assert_eq!(read_wide_c_string(&engine, buffer, 4), "");
    assert_eq!(engine.modules().memory().read_u32(errno_ptr).unwrap(), 34);
}

#[test]
fn msvcrt_wide_numeric_helpers_parse_expected_values() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let wtoi = engine.bind_hook_for_test("msvcrt.dll", "_wtoi");
    let wtol = engine.bind_hook_for_test("msvcrt.dll", "_wtol");
    let wcstol = engine.bind_hook_for_test("msvcrt.dll", "wcstol");
    let wcstoul = engine.bind_hook_for_test("msvcrt.dll", "wcstoul");
    let source = engine.allocate_executable_test_page(0x6347_2000).unwrap();
    let hex = source + 0x100;
    let end_ptr = source + 0x200;

    write_wide_c_string(&mut engine, source, "  -42xyz");
    write_wide_c_string(&mut engine, hex, "0x1fZ");
    write_pointer(&mut engine, end_ptr, 0).unwrap();

    assert_eq!(
        engine.dispatch_bound_stub(wtoi, &[source]).unwrap() as u32 as i32,
        -42
    );
    assert_eq!(
        engine.dispatch_bound_stub(wtol, &[source]).unwrap() as u32 as i32,
        -42
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(wcstol, &[source, end_ptr, 10])
            .unwrap() as u32 as i32,
        -42
    );
    assert_eq!(read_pointer(&engine, end_ptr).unwrap(), source + 10);

    write_pointer(&mut engine, end_ptr, 0).unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(wcstoul, &[hex, end_ptr, 0])
            .unwrap(),
        31
    );
    assert_eq!(read_pointer(&engine, end_ptr).unwrap(), hex + 8);
}

#[test]
fn msvcrt_wcscpy_s_and_wcscmp_round_trip_text() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let wcscpy_s = engine.bind_hook_for_test("msvcrt.dll", "wcscpy_s");
    let wcscmp = engine.bind_hook_for_test("msvcrt.dll", "wcscmp");
    let source = engine.allocate_executable_test_page(0x6347_3000).unwrap();
    let dest = source + 0x100;

    write_wide_c_string(&mut engine, source, "SampleText");
    engine.write_test_bytes(dest, &[0; 64]).unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(wcscpy_s, &[dest, 32, source])
            .unwrap(),
        0
    );
    assert_eq!(read_wide_c_string(&engine, dest, 32), "SampleText");
    assert_eq!(
        engine.dispatch_bound_stub(wcscmp, &[dest, source]).unwrap(),
        0
    );
}

#[test]
fn msvcrt_swprintf_s_formats_inline_decimal_arguments() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let swprintf_s = engine.bind_hook_for_test("msvcrt.dll", "swprintf_s");
    let format_ptr = engine.allocate_executable_test_page(0x6347_4000).unwrap();
    let buffer = format_ptr + 0x100;

    write_wide_c_string(&mut engine, format_ptr, "Value=%d");
    engine.write_test_bytes(buffer, &[0; 128]).unwrap();

    let written = engine
        .dispatch_bound_stub(swprintf_s, &[buffer, 32, format_ptr, 7])
        .unwrap();

    assert_eq!(written, "Value=7".encode_utf16().count() as u64);
    assert_eq!(read_wide_c_string(&engine, buffer, 32), "Value=7");
}

#[test]
fn msvcr100_controlfp_s_reports_previous_and_updates_state() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let controlfp_s = engine.bind_hook_for_test("msvcr100.dll", "_controlfp_s");
    let controlfp = engine.bind_hook_for_test("msvcrt.dll", "_controlfp");
    let current_ptr = engine.allocate_executable_test_page(0x6348_0000).unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(controlfp_s, &[current_ptr, 0x0003_0000, 0x0003_0000])
            .unwrap(),
        0
    );
    assert_eq!(
        engine.modules().memory().read_u32(current_ptr).unwrap(),
        0x0009_001F
    );
    assert_eq!(
        engine.dispatch_bound_stub(controlfp, &[0, 0]).unwrap(),
        0x000B_001F
    );
}

#[test]
fn api_ms_crt_stdio_set_fmode_updates_fmode_cell() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let set_fmode = engine.bind_hook_for_test("api-ms-win-crt-stdio-l1-1-0.dll", "_set_fmode");
    let p_fmode = engine.bind_hook_for_test("msvcrt.dll", "__p__fmode");

    assert_eq!(engine.dispatch_bound_stub(set_fmode, &[0x4000]).unwrap(), 0);
    let fmode_ptr = engine.dispatch_bound_stub(p_fmode, &[]).unwrap();
    assert_eq!(
        engine.modules().memory().read_u32(fmode_ptr).unwrap(),
        0x4000
    );
}

#[test]
fn msvcr100_getenv_returns_runtime_environment_value() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let name = engine.allocate_executable_test_page(0x6348_1000).unwrap();
    engine.write_test_bytes(name, b"SystemRoot\0").unwrap();

    let getenv = engine.bind_hook_for_test("msvcr100.dll", "getenv");
    let result = engine.dispatch_bound_stub(getenv, &[name]).unwrap();

    assert_ne!(result, 0);
    let bytes = engine.modules().memory().read(result, 32).unwrap();
    let length = bytes.iter().position(|byte| *byte == 0).unwrap();
    assert!(String::from_utf8_lossy(&bytes[..length]).starts_with("C:\\"));
}

#[test]
fn api_ms_crt_runtime_configure_argv_variants_return_success() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let narrow = engine.bind_hook_for_test(
        "api-ms-win-crt-runtime-l1-1-0.dll",
        "_configure_narrow_argv",
    );
    let wide =
        engine.bind_hook_for_test("api-ms-win-crt-runtime-l1-1-0.dll", "_configure_wide_argv");

    assert_eq!(engine.dispatch_bound_stub(narrow, &[1]).unwrap(), 0);
    assert_eq!(engine.dispatch_bound_stub(wide, &[1]).unwrap(), 0);
}

#[test]
fn msvcrt_wgetmainargs_exposes_wide_command_line_and_environment() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let wgetmainargs = engine.bind_hook_for_test("msvcrt.dll", "__wgetmainargs");
    let get_command_line_w = engine.bind_hook_for_test("kernel32.dll", "GetCommandLineW");
    let get_environment_strings_w =
        engine.bind_hook_for_test("kernel32.dll", "GetEnvironmentStringsW");
    let page = engine.allocate_executable_test_page(0x6348_2000).unwrap();
    let argc_ptr = page;
    let argv_ptr = page + 0x10;
    let envp_ptr = page + 0x20;

    assert_eq!(
        engine
            .dispatch_bound_stub(wgetmainargs, &[argc_ptr, argv_ptr, envp_ptr, 0, 0])
            .unwrap(),
        0
    );
    assert_eq!(engine.modules().memory().read_u32(argc_ptr).unwrap(), 1);

    let argv = read_pointer(&engine, argv_ptr).unwrap();
    let envp = read_pointer(&engine, envp_ptr).unwrap();
    let command_line = engine.dispatch_bound_stub(get_command_line_w, &[]).unwrap();
    let environment = engine
        .dispatch_bound_stub(get_environment_strings_w, &[])
        .unwrap();

    assert_eq!(read_pointer(&engine, argv).unwrap(), command_line);
    assert_eq!(read_pointer(&engine, envp).unwrap(), environment);
}

fn read_pointer(engine: &VirtualExecutionEngine, address: u64) -> Result<u64, hvm::error::VmError> {
    if engine.modules().arch().is_x86() {
        Ok(engine.modules().memory().read_u32(address)? as u64)
    } else {
        Ok(u64::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(address, 8)?
                .try_into()
                .unwrap(),
        ))
    }
}

fn write_pointer(
    engine: &mut VirtualExecutionEngine,
    address: u64,
    value: u64,
) -> Result<(), hvm::error::VmError> {
    if engine.modules().arch().is_x86() {
        engine.write_test_bytes(address, &(value as u32).to_le_bytes())
    } else {
        engine.write_test_bytes(address, &value.to_le_bytes())
    }
}
