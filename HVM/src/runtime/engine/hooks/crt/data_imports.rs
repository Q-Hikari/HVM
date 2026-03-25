use super::*;
use crate::pe::imports::ImportBinding;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn apply_known_crt_data_import(
        &mut self,
        module_base: u64,
        import: &ImportBinding,
    ) -> Result<bool, VmError> {
        if import.dll.eq_ignore_ascii_case("msvcrt.dll")
            && import.function.eq_ignore_ascii_case("_acmdln")
        {
            let cell = self.ensure_msvcrt_acmdln_cell()?;
            let thunk = module_base + import.offset;
            if import.size == 4 {
                self.write_u32(thunk, cell as u32)?;
            } else {
                self.modules
                    .memory_mut()
                    .write(thunk, &cell.to_le_bytes())?;
            }
            return Ok(true);
        }
        Ok(false)
    }
}
