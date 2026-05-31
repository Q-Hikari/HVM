use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

#[test]
fn ordinal_1895_binds_and_returns_zero() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("mfc100.dll", "ordinal_1895");
    assert_eq!(engine.dispatch_bound_stub(stub, &[]).unwrap(), 0);
}
