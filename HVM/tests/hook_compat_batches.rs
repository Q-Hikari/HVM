use hvm::tests_support::build_loaded_engine;

#[test]
fn synthetic_modules_bind_supported_and_unsupported_exports_consistently() {
    let mut engine = build_loaded_engine();
    let report = engine.bind_representative_hook_exports_for_test();

    assert!(report.bound > 0);
    assert!(report.unsupported_seen > 0);
}
