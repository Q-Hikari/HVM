use super::*;

impl WindowsProcessEnvironment {
    /// Copies the currently active TEB and TLS slots back into pseudo-memory so
    /// later materialization does not clobber runtime-managed thread state.
    pub fn sync_current_thread_from_memory(
        &mut self,
        memory: &MemoryManager,
    ) -> Result<(), MemoryError> {
        let teb_base = self.current_teb_base;
        if memory.is_range_mapped(teb_base, TEB_REGION_SIZE) {
            let bytes = memory.read(teb_base, TEB_REGION_SIZE as usize)?;
            self.write_bytes_inner(teb_base, &bytes, false);
        }
        Ok(())
    }

    /// Mirrors the current process-environment pages into the emulated memory manager.
    pub fn materialize_into(&mut self, memory: &mut MemoryManager) -> Result<(), MemoryError> {
        if !self.dirty {
            return Ok(());
        }
        let dirty_pages = std::mem::take(&mut self.dirty_pages);
        for page_base in dirty_pages {
            self.ensure_region(
                memory,
                page_base,
                PAGE_SIZE,
                self.region_tag_for_page(page_base),
            )?;
            self.copy_region(memory, page_base, PAGE_SIZE as usize)?;
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

    pub(super) fn copy_region(
        &self,
        memory: &mut MemoryManager,
        base: u64,
        size: usize,
    ) -> Result<(), MemoryError> {
        let mut bytes = vec![0u8; size];
        for (offset, byte) in bytes.iter_mut().enumerate() {
            if let Some(value) = self.memory.get(&(base + offset as u64)) {
                *byte = *value;
            }
        }
        memory.write(base, &bytes)
    }

    fn region_tag_for_page(&self, page_base: u64) -> &'static str {
        if Self::page_in_range(page_base, self.layout.peb_base, PEB_REGION_SIZE) {
            return "env:peb";
        }
        if Self::page_in_range(page_base, self.layout.ldr_base, LDR_REGION_SIZE) {
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
