use super::*;

impl WindowsProcessEnvironment {
    pub(in crate::runtime::windows_env) fn write_process_parameters_metadata(&mut self) {
        self.write_u32(
            self.layout.process_parameters_base
                + self.offsets.process_parameters_maximum_length as u64,
            PROCESS_PARAMETERS_REGION_SIZE as u32,
        );
        self.write_u32(
            self.layout.process_parameters_base + self.offsets.process_parameters_length as u64,
            0x80,
        );
    }

    pub(in crate::runtime::windows_env) fn write_unicode_string_descriptor(
        &mut self,
        address: u64,
        buffer: u64,
        value: &str,
    ) {
        let byte_len = value.encode_utf16().count().saturating_mul(2);
        let max_len = byte_len.saturating_add(2);
        self.write_u16(address, byte_len.min(u16::MAX as usize) as u16);
        self.write_u16(address + 2, max_len.min(u16::MAX as usize) as u16);
        let buffer_offset = if self.pointer_size() == 4 { 4 } else { 8 };
        self.write_pointer(address + buffer_offset, buffer);
    }

    pub(in crate::runtime::windows_env) fn write_wide_process_parameter(
        &mut self,
        buffer: u64,
        field_offset: usize,
        value: &str,
    ) -> Result<(), MemoryError> {
        self.write_wide_string(buffer, value)?;
        self.write_unicode_string_descriptor(
            self.layout.process_parameters_base + field_offset as u64,
            buffer,
            value,
        );
        Ok(())
    }

    pub(in crate::runtime::windows_env) fn write_curdir(
        &mut self,
        current_directory: &str,
    ) -> Result<(), MemoryError> {
        self.write_wide_string(self.layout.current_directory_buffer, current_directory)?;
        self.write_unicode_string_descriptor(
            self.layout.process_parameters_base
                + self.offsets.process_parameters_current_directory as u64,
            self.layout.current_directory_buffer,
            current_directory,
        );
        self.write_pointer(
            self.layout.process_parameters_base
                + self.offsets.process_parameters_current_directory as u64
                + self.unicode_string_size() as u64,
            0,
        );
        Ok(())
    }

    pub(in crate::runtime::windows_env) fn unicode_string_size(&self) -> usize {
        if self.pointer_size() == 4 {
            8
        } else {
            16
        }
    }
}
