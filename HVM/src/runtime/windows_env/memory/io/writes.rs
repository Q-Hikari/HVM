use super::*;

impl WindowsProcessEnvironment {
    pub(in crate::runtime::windows_env) fn write_pointer(&mut self, address: u64, value: u64) {
        if self.pointer_size() == 4 {
            self.write_bytes(address, &(value as u32).to_le_bytes());
        } else {
            self.write_bytes(address, &value.to_le_bytes());
        }
    }

    pub(in crate::runtime::windows_env) fn write_u16(&mut self, address: u64, value: u16) {
        self.write_bytes(address, &value.to_le_bytes());
    }

    pub(in crate::runtime::windows_env) fn write_u32(&mut self, address: u64, value: u32) {
        self.write_bytes(address, &value.to_le_bytes());
    }

    pub(in crate::runtime::windows_env) fn write_wide_string(
        &mut self,
        address: u64,
        value: &str,
    ) -> Result<(), MemoryError> {
        let encoded = value
            .encode_utf16()
            .flat_map(|word| word.to_le_bytes())
            .chain([0, 0])
            .collect::<Vec<_>>();
        let reserved = 0x1000usize;
        if encoded.len() > reserved {
            return Err(MemoryError::OutOfMemory {
                size: encoded.len() as u64,
            });
        }
        self.write_zeroes(address, reserved);
        self.write_bytes(address, &encoded);
        Ok(())
    }

    pub(in crate::runtime::windows_env) fn write_ansi_string(
        &mut self,
        address: u64,
        value: &str,
    ) -> Result<(), MemoryError> {
        let mut encoded = value.as_bytes().to_vec();
        encoded.push(0);
        let reserved = 0x1000usize;
        if encoded.len() > reserved {
            return Err(MemoryError::OutOfMemory {
                size: encoded.len() as u64,
            });
        }
        self.write_zeroes(address, reserved);
        self.write_bytes(address, &encoded);
        Ok(())
    }

    pub(in crate::runtime::windows_env) fn write_zeroes(&mut self, address: u64, size: usize) {
        self.write_zeroes_inner(address, size, true);
    }

    pub(in crate::runtime::windows_env) fn write_bytes(&mut self, address: u64, data: &[u8]) {
        self.write_bytes_inner(address, data, true);
    }

    pub(in crate::runtime::windows_env) fn write_zeroes_inner(
        &mut self,
        address: u64,
        size: usize,
        mark_dirty: bool,
    ) {
        self.write_bytes_inner(address, &vec![0; size], mark_dirty);
    }

    pub(in crate::runtime::windows_env) fn write_bytes_inner(
        &mut self,
        address: u64,
        data: &[u8],
        mark_dirty: bool,
    ) {
        let mut changed = false;
        for (offset, byte) in data.iter().enumerate() {
            let target = address + offset as u64;
            if self.memory.get(&target).copied() != Some(*byte) {
                self.memory.insert(target, *byte);
                changed = true;
            }
        }
        if mark_dirty && changed {
            self.dirty = true;
            self.mark_dirty_pages(address, data.len());
        }
    }
}
