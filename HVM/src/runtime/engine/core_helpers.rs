use super::*;

impl VirtualExecutionEngine {
    pub(super) fn active_unicorn_api_and_handle(
        &self,
    ) -> Result<(*const UnicornApi, *mut UcEngine), VmError> {
        let state_ptr = ACTIVE_UNICORN_CONTEXT.with(|slot| slot.get());
        if state_ptr.is_null() {
            return Err(VmError::RuntimeInvariant(
                "active unicorn context missing for msvcrt continuation",
            ));
        }
        let state = unsafe { &*state_ptr };
        Ok((state.api, state.uc))
    }

    pub(super) fn active_unicorn_return_value(&self) -> Result<u64, VmError> {
        let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
        let api = unsafe { &*api_ptr };
        let regid = if self.arch.is_x86() {
            UC_X86_REG_EAX
        } else {
            UC_X86_REG_RAX
        };
        unsafe { api.reg_read_raw(uc, regid) }.map_err(|detail| VmError::NativeExecution {
            op: "uc_reg_read(retval)",
            detail,
        })
    }

    pub(super) fn read_u8(&self, address: u64) -> Result<u8, VmError> {
        self.modules
            .memory()
            .read_u8(address)
            .map_err(VmError::from)
    }

    pub(super) fn read_u16(&self, address: u64) -> Result<u16, VmError> {
        self.modules
            .memory()
            .read_u16(address)
            .map_err(VmError::from)
    }

    pub(super) fn read_u32(&self, address: u64) -> Result<u32, VmError> {
        self.modules
            .memory()
            .read_u32(address)
            .map_err(VmError::from)
    }

    pub(super) fn read_i32(&self, address: u64) -> Result<i32, VmError> {
        Ok(self.read_u32(address)? as i32)
    }

    pub(super) fn read_pointer_value(&self, address: u64) -> Result<u64, VmError> {
        if self.arch.is_x86() {
            Ok(self.read_u32(address)? as u64)
        } else {
            Ok(u64::from_le_bytes(
                self.read_bytes_from_memory(address, 8)?.try_into().unwrap(),
            ))
        }
    }

    pub(super) fn write_u32(&mut self, address: u64, value: u32) -> Result<(), VmError> {
        self.modules
            .memory_mut()
            .write(address, &value.to_le_bytes())
            .map_err(VmError::from)
    }

    pub(super) fn write_pointer_value(&mut self, address: u64, value: u64) -> Result<(), VmError> {
        if self.arch.is_x86() {
            self.write_u32(address, value as u32)
        } else {
            self.modules
                .memory_mut()
                .write(address, &value.to_le_bytes())
                .map_err(VmError::from)
        }
    }

    pub(super) fn refresh_known_data_imports(&mut self) -> Result<(), VmError> {
        for module in self.modules.loaded_modules() {
            if module.synthetic {
                continue;
            }
            self.refresh_known_data_imports_for_module(&module)?;
        }
        Ok(())
    }

    pub(super) fn refresh_known_data_imports_for_module(
        &mut self,
        module: &ModuleRecord,
    ) -> Result<(), VmError> {
        let Some(path) = module.path.as_ref() else {
            return Ok(());
        };
        let bytes = fs::read(path).map_err(|source| VmError::ReadFile {
            path: path.clone(),
            source,
        })?;
        let pe = PE::parse(&bytes).map_err(|source| VmError::ParsePe {
            path: path.clone(),
            source,
        })?;
        let mut reported_missing = BTreeSet::new();
        for import in collect_import_bindings(&pe) {
            let _ = self.apply_known_crt_data_import(module.base, &import)?;

            let missing_key = (
                import.dll.to_ascii_lowercase(),
                import.function.to_ascii_lowercase(),
            );
            if !reported_missing.insert(missing_key) {
                continue;
            }
            let dependency_is_synthetic = self
                .modules
                .get_loaded(&import.dll)
                .map(|dependency| dependency.synthetic)
                .unwrap_or(false);
            if dependency_is_synthetic
                && self
                    .hooks
                    .definition(&import.dll, &import.function)
                    .is_none()
            {
                self.log_unsupported_import(
                    module,
                    &import.dll,
                    &import.function,
                    module.base + import.offset,
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn write_u16(&mut self, address: u64, value: u16) -> Result<(), VmError> {
        self.modules
            .memory_mut()
            .write(address, &value.to_le_bytes())
            .map_err(VmError::from)
    }

    pub(super) fn unsupported_x86(&self, opcode: u8, address: u64) -> VmError {
        VmError::NativeExecution {
            op: "decode",
            detail: format!("unsupported x86 opcode 0x{opcode:02X} at 0x{address:X}"),
        }
    }
}
