use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;

#[test]
fn set_last_error_updates_mapped_teb_slot() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();

    engine.load().unwrap();
    engine.set_last_error(0x1234_5678);

    let teb_last_error =
        engine.process_env().current_teb() + engine.process_env().offsets().teb_last_error as u64;
    assert_eq!(engine.last_error(), 0x1234_5678);
    assert_eq!(
        engine.modules().memory().read_u32(teb_last_error).unwrap(),
        0x1234_5678
    );
}
