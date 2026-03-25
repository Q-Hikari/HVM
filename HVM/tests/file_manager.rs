use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::EngineConfig;
use hvm::managers::file_manager::FileManager;

#[test]
fn file_manager_ignores_empty_mapping_file() {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let output_dir = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-file-manager-{timestamp}"
    ));
    fs::create_dir_all(&output_dir).unwrap();
    fs::write(output_dir.join("file_redirects.json"), "").unwrap();

    let config = EngineConfig::for_tests(PathBuf::from(&output_dir));
    let manager = FileManager::new(&config).unwrap();

    assert!(manager.mapping().is_empty());

    fs::remove_dir_all(output_dir).unwrap();
}
