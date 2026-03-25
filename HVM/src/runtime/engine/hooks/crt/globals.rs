use super::*;

impl VirtualExecutionEngine {
    pub(super) fn ensure_msvcrt_globals(&mut self) -> Result<u64, VmError> {
        if let Some(base) = self.msvcrt_globals_base {
            return Ok(base);
        }
        let base = self
            .modules
            .memory_mut()
            .reserve(PAGE_SIZE, None, "msvcrt:globals", true)?;
        self.write_u32(base + MSVCRT_FMODE_OFFSET, 0)?;
        self.write_u32(base + MSVCRT_COMMODE_OFFSET, 0)?;
        self.write_u32(base + MSVCRT_APP_TYPE_OFFSET, 0)?;
        self.write_u32(base + MSVCRT_CONTROLFP_OFFSET, MSVCRT_DEFAULT_CONTROLFP)?;
        self.write_u32(base + MSVCRT_ERRNO_OFFSET, 0)?;
        self.modules
            .memory_mut()
            .write(base + MSVCRT_USER_MATHERR_OFFSET, &0u64.to_le_bytes())?;
        self.write_pointer_value(base + MSVCRT_ONEXIT_TABLE_OFFSET, 0)?;
        self.write_pointer_value(
            base + MSVCRT_ONEXIT_TABLE_OFFSET + self.arch.pointer_size as u64,
            0,
        )?;
        self.write_pointer_value(
            base + MSVCRT_ONEXIT_TABLE_OFFSET + (self.arch.pointer_size as u64 * 2),
            0,
        )?;
        self.modules
            .memory_mut()
            .write(base + MSVCRT_STRERROR_BUFFER_OFFSET, b"Unknown error\0")?;
        self.msvcrt_globals_base = Some(base);
        Ok(base)
    }

    pub(super) fn ensure_msvcrt_acmdln_cell(&mut self) -> Result<u64, VmError> {
        let base = self.ensure_msvcrt_globals()?;
        let cell = base + MSVCRT_ACMDLN_PTR_OFFSET;
        let command_line = self.process_env.layout().command_line_ansi_buffer;
        self.write_pointer_value(cell, command_line)?;
        Ok(cell)
    }

    pub(super) fn ensure_msvcrt_errno_cell(&mut self) -> Result<u64, VmError> {
        Ok(self.ensure_msvcrt_globals()? + MSVCRT_ERRNO_OFFSET)
    }

    pub(super) fn ensure_msvcrt_strerror_buffer(&mut self) -> Result<u64, VmError> {
        Ok(self.ensure_msvcrt_globals()? + MSVCRT_STRERROR_BUFFER_OFFSET)
    }

    pub(super) fn ensure_msvcrt_global_onexit_table(&mut self) -> Result<u64, VmError> {
        Ok(self.ensure_msvcrt_globals()? + MSVCRT_ONEXIT_TABLE_OFFSET)
    }
}
