use super::*;

impl WindowsProcessEnvironment {
    pub(in crate::runtime::windows_env::process::loader) fn read_loader_string(
        &self,
        descriptor: u64,
    ) -> Result<String, MemoryError> {
        let length = self.read_u16(descriptor)? as usize;
        let buffer_offset = if self.pointer_size() == 4 { 4 } else { 8 };
        let buffer = self.read_pointer(descriptor + buffer_offset as u64)?;
        if length == 0 || buffer == 0 {
            return Ok(String::new());
        }
        let bytes = self.read_bytes(buffer, length)?;
        Ok(String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        ))
    }
}

pub(in crate::runtime::windows_env::process::loader) fn encode_loader_string(
    value: &str,
) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0, 0])
        .collect()
}
