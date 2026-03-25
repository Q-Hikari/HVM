use std::collections::BTreeMap;

use crate::managers::handle_table::HandleTable;

/// Stores the emulated metadata for one spawned child process record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    pub handle: u32,
    pub image_path: String,
    pub command_line: String,
    pub current_directory: String,
}

/// Tracks synthetic child processes created by ShellExecute-style APIs.
#[derive(Debug)]
pub struct ProcessManager {
    handles: HandleTable,
    processes: BTreeMap<u32, ProcessRecord>,
}

impl ProcessManager {
    /// Builds a test-only process manager.
    pub fn for_tests() -> Self {
        Self {
            handles: HandleTable::new(0x9000),
            processes: BTreeMap::new(),
        }
    }

    /// Creates a synthetic child-process record and returns its handle.
    pub fn spawn_shell_execute(
        &mut self,
        image: &str,
        parameters: Option<&str>,
        cwd: Option<&str>,
    ) -> Option<u32> {
        let handle = self.handles.allocate("process", ());
        let command_line = match parameters.filter(|value| !value.is_empty()) {
            Some(parameters) => format!("{image} {parameters}"),
            None => image.to_string(),
        };
        let record = ProcessRecord {
            handle,
            image_path: image.to_string(),
            command_line,
            current_directory: cwd.unwrap_or_default().to_string(),
        };
        self.processes.insert(handle, record);
        Some(handle)
    }

    /// Finds a process record by its emulated process handle.
    pub fn find_process_by_handle(&self, handle: u32) -> Option<&ProcessRecord> {
        self.processes.get(&handle)
    }

    /// Returns the most recently spawned child-process record if one exists.
    pub fn latest_process(&self) -> Option<&ProcessRecord> {
        self.processes.values().next_back()
    }
}
