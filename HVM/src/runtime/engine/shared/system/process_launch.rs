use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn write_process_information(
        &mut self,
        address: u64,
        process_handle: u32,
        thread_handle: u32,
        process_id: u32,
        thread_id: u32,
    ) -> Result<(), VmError> {
        if address == 0 {
            return Ok(());
        }
        if self.arch.is_x86() {
            let mut payload = [0u8; 16];
            payload[0..4].copy_from_slice(&process_handle.to_le_bytes());
            payload[4..8].copy_from_slice(&thread_handle.to_le_bytes());
            payload[8..12].copy_from_slice(&process_id.to_le_bytes());
            payload[12..16].copy_from_slice(&thread_id.to_le_bytes());
            self.modules.memory_mut().write(address, &payload)?;
        } else {
            let mut payload = [0u8; 24];
            payload[0..8].copy_from_slice(&(process_handle as u64).to_le_bytes());
            payload[8..16].copy_from_slice(&(thread_handle as u64).to_le_bytes());
            payload[16..20].copy_from_slice(&process_id.to_le_bytes());
            payload[20..24].copy_from_slice(&thread_id.to_le_bytes());
            self.modules.memory_mut().write(address, &payload)?;
        }
        Ok(())
    }

    pub(in crate::runtime::engine) fn log_process_spawn(
        &mut self,
        source: &str,
        handle: u32,
        image_path: &str,
        command_line: &str,
        current_directory: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("source".to_string(), json!(source));
        fields.insert("process_handle".to_string(), json!(handle));
        fields.insert("image_path".to_string(), json!(image_path));
        fields.insert("command_line".to_string(), json!(command_line));
        fields.insert("current_directory".to_string(), json!(current_directory));
        self.log_runtime_event("PROCESS_SPAWN", fields)
    }
}
