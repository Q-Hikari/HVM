use super::*;

impl WindowsProcessEnvironment {
    pub(in crate::runtime::windows_env) fn initialize_tls_bitmap_layout(&mut self) {
        self.write_zeroes(self.layout.tls_bitmap_base, PROCESS_BUFFER_SIZE as usize);
        self.write_zeroes(self.layout.tls_bitmap_buffer, PROCESS_BUFFER_SIZE as usize);
        self.write_u32(self.layout.tls_bitmap_base, 64);
        self.write_pointer(
            self.layout.tls_bitmap_base + self.pointer_size() as u64,
            self.layout.tls_bitmap_buffer,
        );
    }

    pub(in crate::runtime::windows_env) fn set_bitmap_bit(&mut self, slot: usize) {
        let word_offset = ((slot / 32) * 4) as u64;
        let bit = slot % 32;
        let current = self
            .read_u32(self.layout.tls_bitmap_buffer + word_offset)
            .unwrap_or(0);
        self.write_u32(
            self.layout.tls_bitmap_buffer + word_offset,
            current | (1 << bit),
        );
    }

    pub(in crate::runtime::windows_env) fn clear_bitmap_bit(&mut self, slot: usize) {
        let word_offset = ((slot / 32) * 4) as u64;
        let bit = slot % 32;
        let current = self
            .read_u32(self.layout.tls_bitmap_buffer + word_offset)
            .unwrap_or(0);
        self.write_u32(
            self.layout.tls_bitmap_buffer + word_offset,
            current & !(1 << bit),
        );
    }
}
