use std::collections::BTreeMap;
use std::fs;

use crate::config::EngineConfig;

/// Loads file redirection metadata and exposes the normalized mapping table.
#[derive(Debug, Default)]
pub struct FileManager {
    mapping: BTreeMap<String, String>,
}

impl FileManager {
    /// Builds the file manager from the current engine config.
    pub fn new(config: &EngineConfig) -> Result<Self, std::io::Error> {
        let redirects_path = config.sandbox_output_dir.join("file_redirects.json");
        let mapping = match fs::read_to_string(&redirects_path) {
            Ok(content) if content.trim().is_empty() => BTreeMap::new(),
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error),
        };
        Ok(Self { mapping })
    }

    /// Returns the currently loaded redirect mapping table.
    pub fn mapping(&self) -> &BTreeMap<String, String> {
        &self.mapping
    }
}
