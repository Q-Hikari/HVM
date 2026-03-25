use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;

const REGDB_E_CLASSNOTREG_HRESULT: u64 = 0x8004_0154;

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

fn read_wide_c_string(engine: &VirtualExecutionEngine, address: u64, max_chars: usize) -> String {
    let bytes = engine
        .modules()
        .memory()
        .read(address, max_chars.saturating_mul(2))
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

#[test]
fn co_create_guid_writes_uuid4_like_bytes() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let buffer = engine.allocate_executable_test_page(0x7200_0000).unwrap();
    engine.write_test_bytes(buffer, &[0; 0x100]).unwrap();

    let stub = engine.bind_hook_for_test("ole32.dll", "CoCreateGuid");
    assert_eq!(engine.dispatch_bound_stub(stub, &[buffer]).unwrap(), 0);
    let first = engine.modules().memory().read(buffer, 16).unwrap();
    assert!(first.iter().any(|byte| *byte != 0));
    assert_eq!(first[7] >> 4, 4);
    assert_eq!(first[8] & 0xC0, 0x80);

    assert_eq!(engine.dispatch_bound_stub(stub, &[buffer]).unwrap(), 0);
    let second = engine.modules().memory().read(buffer, 16).unwrap();
    assert_ne!(first, second);
    assert_eq!(second[7] >> 4, 4);
    assert_eq!(second[8] & 0xC0, 0x80);
}

#[test]
fn string_from_guid2_formats_python_style_uppercase_text() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let guid_ptr = engine.allocate_executable_test_page(0x7201_0000).unwrap();
    let buffer = engine.allocate_executable_test_page(0x7202_0000).unwrap();
    engine.write_test_bytes(buffer, &[0; 0x200]).unwrap();
    engine
        .write_test_bytes(
            guid_ptr,
            &[
                0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF,
            ],
        )
        .unwrap();

    let stub = engine.bind_hook_for_test("combase.dll", "StringFromGUID2");
    let retval = engine
        .dispatch_bound_stub(stub, &[guid_ptr, buffer, 64])
        .unwrap();

    assert_eq!(retval, 39);
    assert_eq!(
        read_wide_c_string(&engine, buffer, 64),
        "{00112233-4455-6677-8899-AABBCCDDEEFF}"
    );
}

#[test]
fn uuid_create_sequential_returns_local_only_and_writes_version1_bytes() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let buffer = engine.allocate_executable_test_page(0x7203_0000).unwrap();
    engine.write_test_bytes(buffer, &[0; 0x100]).unwrap();

    let stub = engine.bind_hook_for_test("rpcrt4.dll", "UuidCreateSequential");
    let retval = engine.dispatch_bound_stub(stub, &[buffer]).unwrap();
    let guid = engine.modules().memory().read(buffer, 16).unwrap();

    assert_eq!(retval, 1824);
    assert!(guid.iter().any(|byte| *byte != 0));
    assert_eq!(guid[7] >> 4, 1);
    assert_eq!(guid[8] & 0xC0, 0x80);
}

#[test]
fn co_create_instance_returns_class_not_registered_and_clears_output_pointer() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let object_ptr = engine.allocate_executable_test_page(0x7204_0000).unwrap();
    if engine
        .entry_module()
        .or_else(|| engine.main_module())
        .map(|module| module.arch.eq_ignore_ascii_case("x64"))
        .unwrap_or(false)
    {
        engine
            .write_test_bytes(object_ptr, &0x1111_2222_3333_4444u64.to_le_bytes())
            .unwrap();
    } else {
        engine
            .write_test_bytes(object_ptr, &0x1111_2222u32.to_le_bytes())
            .unwrap();
    }

    let stub = engine.bind_hook_for_test("ole32.dll", "CoCreateInstance");
    let retval = engine
        .dispatch_bound_stub(stub, &[0, 0, 1, 0, object_ptr])
        .unwrap();

    assert_eq!(retval, REGDB_E_CLASSNOTREG_HRESULT);
    let cleared = if engine
        .entry_module()
        .or_else(|| engine.main_module())
        .map(|module| module.arch.eq_ignore_ascii_case("x64"))
        .unwrap_or(false)
    {
        u64::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(object_ptr, 8)
                .unwrap()
                .try_into()
                .unwrap(),
        )
    } else {
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(object_ptr, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ) as u64
    };
    assert_eq!(cleared, 0);
}
