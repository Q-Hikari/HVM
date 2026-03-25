use super::*;

impl WindowsProcessEnvironment {
    /// Returns whether the mirrored TLS bitmap has the requested bit set.
    pub fn is_tls_bit_set(&self, slot: usize) -> Result<bool, MemoryError> {
        let word_offset = ((slot / 32) * 4) as u64;
        let bit = slot % 32;
        let raw = self.read_u32(self.layout.tls_bitmap_buffer + word_offset)?;
        Ok(((raw >> bit) & 1) == 1)
    }

    /// Reads an emulated pointer-sized value from pseudo-memory.
    pub fn read_pointer(&self, address: u64) -> Result<u64, MemoryError> {
        if self.pointer_size() == 4 {
            let bytes = self.read_bytes(address, 4)?;
            Ok(u32::from_le_bytes(bytes.try_into().unwrap()) as u64)
        } else {
            let bytes = self.read_bytes(address, 8)?;
            Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
        }
    }

    /// Reads one UTF-16 string from pseudo-memory until its terminating null.
    pub fn read_wide_string(&self, address: u64) -> Result<String, MemoryError> {
        let mut bytes = Vec::new();
        let mut cursor = address;
        loop {
            let word = self.read_bytes(cursor, 2)?;
            if word == [0, 0] {
                break;
            }
            bytes.extend_from_slice(&word);
            cursor += 2;
        }
        Ok(String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        ))
    }

    pub(in crate::runtime::windows_env) fn read_u32(
        &self,
        address: u64,
    ) -> Result<u32, MemoryError> {
        let bytes = self.read_bytes(address, 4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub(in crate::runtime::windows_env) fn read_u16(
        &self,
        address: u64,
    ) -> Result<u16, MemoryError> {
        let bytes = self.read_bytes(address, 2)?;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub(in crate::runtime::windows_env) fn read_bytes(
        &self,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, MemoryError> {
        let mut bytes = Vec::with_capacity(size);
        for offset in 0..size {
            let target = address + offset as u64;
            bytes.push(*self.memory.get(&target).ok_or(MemoryError::MissingRegion {
                address,
                size: size as u64,
            })?);
        }
        Ok(bytes)
    }
}
