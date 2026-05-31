use super::*;

impl WindowsProcessEnvironment {
    pub(in crate::runtime::windows_env) fn write_pointer(&mut self, address: u64, value: u64) {
        if self.pointer_size() == 4 {
            self.write_bytes(address, &(value as u32).to_le_bytes());
        } else {
            self.write_bytes(address, &value.to_le_bytes());
        }
    }

    pub(in crate::runtime::windows_env) fn write_u8(&mut self, address: u64, value: u8) {
        self.write_bytes(address, &[value]);
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
                tag: Some("windows_env:wide_string_buffer".to_string()),
                preferred: None,
                avoid_history: None,
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
                tag: Some("windows_env:ansi_string_buffer".to_string()),
                preferred: None,
                avoid_history: None,
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
        if size == 0 {
            return;
        }
        let mut changed = false;
        let mut cursor = address;
        let end = address.saturating_add(size as u64);
        while cursor < end {
            let page_base = cursor & !(PAGE_SIZE - 1);
            let offset = (cursor - page_base) as usize;
            let chunk_len = ((PAGE_SIZE as usize) - offset).min((end - cursor) as usize);
            let page = self.page_mut(page_base);
            if page[offset..offset + chunk_len]
                .iter()
                .any(|byte| *byte != 0)
            {
                page[offset..offset + chunk_len].fill(0);
                changed = true;
            }
            cursor = cursor.saturating_add(chunk_len as u64);
        }
        if mark_dirty && changed {
            self.dirty = true;
            self.mark_dirty_pages(address, size);
        }
    }

    pub(in crate::runtime::windows_env) fn write_bytes_inner(
        &mut self,
        address: u64,
        data: &[u8],
        mark_dirty: bool,
    ) {
        if data.is_empty() {
            return;
        }
        let mut changed = false;
        let mut written = 0usize;
        let end = address.saturating_add(data.len() as u64);
        let mut cursor = address;
        while cursor < end {
            let page_base = cursor & !(PAGE_SIZE - 1);
            let offset = (cursor - page_base) as usize;
            let chunk_len = ((PAGE_SIZE as usize) - offset).min(data.len() - written);
            let page = self.page_mut(page_base);
            let source = &data[written..written + chunk_len];
            if page[offset..offset + chunk_len] != *source {
                page[offset..offset + chunk_len].copy_from_slice(source);
                changed = true;
            }
            written += chunk_len;
            cursor = cursor.saturating_add(chunk_len as u64);
        }
        if mark_dirty && changed {
            self.dirty = true;
            self.mark_dirty_pages(address, data.len());
        }
    }

    fn page_mut(&mut self, page_base: u64) -> &mut EnvironmentPage {
        self.memory
            .entry(page_base)
            .or_insert_with(|| Box::new([0u8; PAGE_SIZE as usize]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_and_write_bytes_across_page_boundaries() {
        let mut env = WindowsProcessEnvironment::for_tests_x86();
        let address = env.current_teb() + PAGE_SIZE - 2;
        env.write_bytes(address, &[0x11, 0x22, 0x33, 0x44]);

        assert_eq!(
            env.read_bytes(address, 4).unwrap(),
            vec![0x11, 0x22, 0x33, 0x44]
        );
    }
}
