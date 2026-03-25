use super::*;

impl WindowsProcessEnvironment {
    pub(in crate::runtime::windows_env) fn refresh_x86_gdt(&mut self, teb_base: u64) {
        let entries = [
            [0u8; 8],
            Self::segment_descriptor(0, 0xFFFFF, 0x9A, 0x0C),
            Self::segment_descriptor(0, 0xFFFFF, 0x92, 0x0C),
            Self::segment_descriptor(teb_base, 0x1FFF, 0x92, 0x04),
        ];
        self.write_zeroes(self.layout.gdt_base, GDT_REGION_SIZE as usize);
        for (index, entry) in entries.into_iter().enumerate() {
            self.write_bytes(self.layout.gdt_base + index as u64 * 8, &entry);
        }
    }

    fn segment_descriptor(base: u64, limit: u32, access: u8, flags: u8) -> [u8; 8] {
        let mut value = 0u64;
        value |= limit as u64 & 0xFFFF;
        value |= (base & 0xFFFF) << 16;
        value |= ((base >> 16) & 0xFF) << 32;
        value |= (access as u64) << 40;
        value |= (((limit >> 16) & 0x0F) as u64) << 48;
        value |= ((flags as u64) & 0x0F) << 52;
        value |= ((base >> 24) & 0xFF) << 56;
        value.to_le_bytes()
    }
}
