use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

#[test]
fn get_keyboard_type_reports_standard_101_102_keyboard_shape() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("user32.dll", "GetKeyboardType");
    assert_eq!(engine.dispatch_bound_stub(stub, &[0]).unwrap(), 4);
    assert_eq!(engine.dispatch_bound_stub(stub, &[1]).unwrap(), 0);
    assert_eq!(engine.dispatch_bound_stub(stub, &[2]).unwrap(), 12);
}

#[test]
fn load_string_w_returns_stubbed_resource_text() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("user32.dll", "LoadStringW");
    let buffer = engine.allocate_executable_test_page(0x6600_0000).unwrap();
    engine.write_test_bytes(buffer, &[0xAA; 32]).unwrap();

    let written = engine
        .dispatch_bound_stub(stub, &[0, 1, buffer, 16])
        .unwrap();

    assert_eq!(written, 8);
    let bytes = engine.modules().memory().read(buffer, 18).unwrap();
    let words = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|word| *word != 0)
        .collect::<Vec<_>>();
    assert_eq!(String::from_utf16(&words).unwrap(), "resource");
}
