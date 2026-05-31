use super::*;

impl WindowsProcessEnvironment {
    /// Copies the currently active TEB and TLS slots back into pseudo-memory so
    /// later materialization does not clobber runtime-managed thread state.
    pub fn sync_current_thread_from_memory(
        &mut self,
        memory: &MemoryManager,
    ) -> Result<(), MemoryError> {
        let teb_base = self.current_teb_base;
        let teb_end = teb_base.saturating_add(TEB_REGION_SIZE);
        let mut page_base = teb_base & !(PAGE_SIZE - 1);
        while page_base < teb_end {
            if !memory.is_range_mapped(page_base, PAGE_SIZE) {
                page_base = page_base.saturating_add(PAGE_SIZE);
                continue;
            }
            let bytes = memory.read(page_base, PAGE_SIZE as usize)?;
            self.write_bytes_inner(page_base, &bytes, false);
            page_base = page_base.saturating_add(PAGE_SIZE);
        }
        Ok(())
    }

    /// Mirrors the current process-environment pages into the emulated memory manager.
    pub fn materialize_into(&mut self, memory: &mut MemoryManager) -> Result<(), MemoryError> {
        if !self.dirty {
            return Ok(());
        }
        let dirty_pages = std::mem::take(&mut self.dirty_pages);
        let mut page_buffer = vec![0u8; PAGE_SIZE as usize];
        for page_base in dirty_pages {
            self.ensure_region(
                memory,
                page_base,
                PAGE_SIZE,
                self.region_tag_for_page(page_base),
            )?;
            self.copy_region_into(memory, page_base, &mut page_buffer)?;
        }

        self.dirty = false;
        Ok(())
    }

    pub(super) fn ensure_region(
        &self,
        memory: &mut MemoryManager,
        base: u64,
        size: u64,
        tag: &str,
    ) -> Result<(), MemoryError> {
        if !memory.is_range_mapped(base, size) {
            memory.reserve(size, Some(base), tag, false)?;
        }
        Ok(())
    }

    pub(super) fn copy_region_into(
        &self,
        memory: &mut MemoryManager,
        base: u64,
        buffer: &mut [u8],
    ) -> Result<(), MemoryError> {
        buffer.fill(0);
        let mut cursor = base;
        let end = base.saturating_add(buffer.len() as u64);
        while cursor < end {
            let page_base = cursor & !(PAGE_SIZE - 1);
            let page_offset = (cursor - page_base) as usize;
            let chunk_len = ((PAGE_SIZE as usize) - page_offset).min((end - cursor) as usize);
            if let Some(page) = self.memory.get(&page_base) {
                let buffer_offset = (cursor - base) as usize;
                buffer[buffer_offset..buffer_offset + chunk_len]
                    .copy_from_slice(&page[page_offset..page_offset + chunk_len]);
            }
            cursor = cursor.saturating_add(chunk_len as u64);
        }
        memory.write(base, buffer)
    }

    fn region_tag_for_page(&self, page_base: u64) -> &'static str {
        if Self::page_in_range(page_base, self.layout.peb_base, PEB_REGION_SIZE) {
            return "env:peb";
        }
        if Self::page_in_range(page_base, self.layout.ldr_base, self.loader_region_size()) {
            return "env:ldr";
        }
        if Self::page_in_range(
            page_base,
            self.layout.process_parameters_base,
            PROCESS_PARAMETERS_REGION_SIZE,
        ) {
            return "env:process_parameters";
        }
        if Self::page_in_range(page_base, self.layout.tls_bitmap_base, PROCESS_BUFFER_SIZE)
            || Self::page_in_range(
                page_base,
                self.layout.tls_bitmap_buffer,
                PROCESS_BUFFER_SIZE,
            )
        {
            return "env:tls_bitmap";
        }
        if Self::page_in_range(
            page_base,
            self.layout.image_path_buffer,
            PROCESS_BUFFER_SIZE,
        ) {
            return "env:image_path";
        }
        if Self::page_in_range(
            page_base,
            self.layout.command_line_buffer,
            PROCESS_BUFFER_SIZE,
        ) {
            return "env:command_line_w";
        }
        if Self::page_in_range(
            page_base,
            self.layout.command_line_ansi_buffer,
            PROCESS_BUFFER_SIZE,
        ) {
            return "env:command_line_a";
        }
        if Self::page_in_range(
            page_base,
            self.layout.current_directory_buffer,
            PROCESS_BUFFER_SIZE,
        ) {
            return "env:current_directory";
        }
        if Self::page_in_range(page_base, self.layout.dll_path_buffer, PROCESS_BUFFER_SIZE) {
            return "env:dll_path";
        }
        if Self::page_in_range(
            page_base,
            self.layout.environment_w_buffer,
            ENVIRONMENT_W_BUFFER_SIZE,
        ) {
            return "env:environment_w";
        }
        if Self::page_in_range(
            page_base,
            self.layout.environment_a_buffer,
            ENVIRONMENT_A_BUFFER_SIZE,
        ) {
            return "env:environment_a";
        }
        if self.layout.gdt_base != 0
            && Self::page_in_range(page_base, self.layout.gdt_base, GDT_REGION_SIZE)
        {
            return "env:gdt";
        }
        if self
            .thread_contexts
            .keys()
            .copied()
            .any(|teb_base| Self::page_in_range(page_base, teb_base, TEB_REGION_SIZE))
        {
            return "env:teb";
        }
        "env:page"
    }

    fn page_in_range(page_base: u64, base: u64, size: u64) -> bool {
        let end = base.saturating_add(size);
        page_base >= base && page_base < end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::manager::{MemoryManager, PROT_READ, PROT_WRITE};

    #[test]
    fn sync_current_thread_from_memory_refreshes_live_teb_pages() {
        let mut env = WindowsProcessEnvironment::for_tests_x86();
        env.dirty = false;
        env.dirty_pages.clear();
        let teb_base = env.current_teb();
        let peb_base = env.current_peb();
        let mut memory = MemoryManager::for_tests();
        memory
            .map_region(teb_base, TEB_REGION_SIZE, PROT_READ | PROT_WRITE, "teb")
            .unwrap();

        env.write_bytes_inner(teb_base, &[0x11], false);
        memory.write(teb_base, &[0x22]).unwrap();
        env.write_bytes(peb_base, &[0xAA]);

        env.sync_current_thread_from_memory(&memory).unwrap();
        assert_eq!(env.read_bytes(teb_base, 1).unwrap(), vec![0x22]);
    }
}
