use std::ffi::c_int;

use super::*;
use crate::api_set::{aliased_host_module, contract_hook_family};
use crate::runtime::api_logger::{ApiExecutionContext, ApiStackWord};

impl VirtualExecutionEngine {
    pub(super) fn has_active_unicorn_context(&self) -> bool {
        ACTIVE_UNICORN_CONTEXT.with(|slot| !slot.get().is_null())
    }

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
        let unicorn = unsafe { api.bind(uc) };
        unicorn
            .reg_read(self.return_value_register())
            .map_err(|detail| VmError::NativeExecution {
                op: "uc_reg_read(retval)",
                detail,
            })
    }

    pub(super) fn active_unicorn_register_value(
        &self,
        regid: c_int,
        label: &'static str,
    ) -> Result<u64, VmError> {
        let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
        let api = unsafe { &*api_ptr };
        let unicorn = unsafe { api.bind(uc) };
        unicorn
            .reg_read(regid)
            .map_err(|detail| VmError::NativeExecution { op: label, detail })
    }

    pub(super) fn active_unicorn_pointer_value(&self, address: u64) -> Result<u64, VmError> {
        let pointer_size = if self.core.arch.is_x86() { 4 } else { 8 };
        let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
        let api = unsafe { &*api_ptr };
        let unicorn = unsafe { api.bind(uc) };
        let bytes =
            unicorn
                .mem_read(address, pointer_size)
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_mem_read(stack)",
                    detail,
                })?;
        if self.core.arch.is_x86() {
            Ok(u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64)
        } else {
            Ok(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
        }
    }

    pub(super) fn capture_active_api_execution_context(
        &self,
        fallback_pc: u64,
        stack_word_count: usize,
    ) -> Result<Option<ApiExecutionContext>, VmError> {
        let (ip, sp, bp, ax, bx, cx, dx, si, di, flags) = if self.core.arch.is_x86() {
            (
                self.active_unicorn_register_value(UC_X86_REG_EIP, "uc_reg_read(eip)")?,
                self.active_unicorn_register_value(UC_X86_REG_ESP, "uc_reg_read(esp)")?,
                self.active_unicorn_register_value(UC_X86_REG_EBP, "uc_reg_read(ebp)")?,
                self.active_unicorn_register_value(UC_X86_REG_EAX, "uc_reg_read(eax)")?,
                self.active_unicorn_register_value(UC_X86_REG_EBX, "uc_reg_read(ebx)")?,
                self.active_unicorn_register_value(UC_X86_REG_ECX, "uc_reg_read(ecx)")?,
                self.active_unicorn_register_value(UC_X86_REG_EDX, "uc_reg_read(edx)")?,
                self.active_unicorn_register_value(UC_X86_REG_ESI, "uc_reg_read(esi)")?,
                self.active_unicorn_register_value(UC_X86_REG_EDI, "uc_reg_read(edi)")?,
                self.active_unicorn_register_value(UC_X86_REG_EFLAGS, "uc_reg_read(eflags)")?,
            )
        } else {
            (
                self.active_unicorn_register_value(UC_X86_REG_RIP, "uc_reg_read(rip)")?,
                self.active_unicorn_register_value(UC_X86_REG_RSP, "uc_reg_read(rsp)")?,
                self.active_unicorn_register_value(UC_X86_REG_RBP, "uc_reg_read(rbp)")?,
                self.active_unicorn_register_value(UC_X86_REG_RAX, "uc_reg_read(rax)")?,
                self.active_unicorn_register_value(UC_X86_REG_RBX, "uc_reg_read(rbx)")?,
                self.active_unicorn_register_value(UC_X86_REG_RCX, "uc_reg_read(rcx)")?,
                self.active_unicorn_register_value(UC_X86_REG_RDX, "uc_reg_read(rdx)")?,
                self.active_unicorn_register_value(UC_X86_REG_RSI, "uc_reg_read(rsi)")?,
                self.active_unicorn_register_value(UC_X86_REG_RDI, "uc_reg_read(rdi)")?,
                self.active_unicorn_register_value(UC_X86_REG_RFLAGS, "uc_reg_read(rflags)")?,
            )
        };

        let pointer_size = if self.core.arch.is_x86() { 4u64 } else { 8u64 };
        let stack_words = (0..stack_word_count)
            .map(|index| {
                let address = sp.saturating_add((index as u64).saturating_mul(pointer_size));
                match self.active_unicorn_pointer_value(address) {
                    Ok(value) => ApiStackWord {
                        address,
                        value: Some(value),
                        value_ref: (value != 0).then(|| self.address_ref(value)),
                        read_error: None,
                    },
                    Err(error) => ApiStackWord {
                        address,
                        value: None,
                        value_ref: None,
                        read_error: Some(error.to_string()),
                    },
                }
            })
            .collect::<Vec<_>>();

        Ok(Some(ApiExecutionContext {
            ip: if ip == 0 { fallback_pc } else { ip },
            sp,
            bp,
            ax,
            bx,
            cx,
            dx,
            si,
            di,
            flags,
            direction_flag: ((flags >> 10) & 1) != 0,
            stack_words,
        }))
    }

    /// Writes the hook return value to the architecture-appropriate register (EAX or RAX).
    #[allow(dead_code)]
    pub(super) fn write_active_return_value(&self, value: u64) -> Result<(), VmError> {
        let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
        let api = unsafe { &*api_ptr };
        let unicorn = unsafe { api.bind(uc) };
        unicorn
            .reg_write(self.return_value_register(), value)
            .map_err(|detail| VmError::NativeExecution {
                op: "uc_reg_write(retval)",
                detail,
            })
    }

    /// Returns the unicorn register ID for the primary return-value register.
    pub(super) fn return_value_register(&self) -> c_int {
        if self.core.arch.is_x86() {
            UC_X86_REG_EAX
        } else {
            UC_X86_REG_RAX
        }
    }

    /// Returns the unicorn register ID for the stack-pointer register.
    #[allow(dead_code)]
    pub(super) fn stack_pointer_register(&self) -> c_int {
        if self.core.arch.is_x86() {
            UC_X86_REG_ESP
        } else {
            UC_X86_REG_RSP
        }
    }

    /// Returns the unicorn register ID for the instruction-pointer register.
    pub(super) fn instruction_pointer_register(&self) -> c_int {
        if self.core.arch.is_x86() {
            UC_X86_REG_EIP
        } else {
            UC_X86_REG_RIP
        }
    }

    pub(super) fn read_u8(&self, address: u64) -> Result<u8, VmError> {
        Ok(self.read_bytes_with_guest_fault(address, 1)?[0])
    }

    pub(super) fn read_u16(&self, address: u64) -> Result<u16, VmError> {
        Ok(u16::from_le_bytes(
            self.read_bytes_with_guest_fault(address, 2)?
                .as_slice()
                .try_into()
                .unwrap(),
        ))
    }

    pub(super) fn read_u32(&self, address: u64) -> Result<u32, VmError> {
        Ok(u32::from_le_bytes(
            self.read_bytes_with_guest_fault(address, 4)?
                .as_slice()
                .try_into()
                .unwrap(),
        ))
    }

    pub(super) fn read_i32(&self, address: u64) -> Result<i32, VmError> {
        Ok(self.read_u32(address)? as i32)
    }

    pub(super) fn read_pointer_value(&self, address: u64) -> Result<u64, VmError> {
        if self.core.arch.is_x86() {
            Ok(self.read_u32(address)? as u64)
        } else {
            Ok(u64::from_le_bytes(
                self.read_bytes_from_memory(address, 8)?.try_into().unwrap(),
            ))
        }
    }

    pub(super) fn write_u32(&mut self, address: u64, value: u32) -> Result<(), VmError> {
        self.core
            .modules
            .memory_mut()
            .write(address, &value.to_le_bytes())
            .map_err(VmError::from)
    }

    pub(super) fn write_pointer_value(&mut self, address: u64, value: u64) -> Result<(), VmError> {
        if self.core.arch.is_x86() {
            self.write_u32(address, value as u32)
        } else {
            self.core
                .modules
                .memory_mut()
                .write(address, &value.to_le_bytes())
                .map_err(VmError::from)
        }
    }

    pub(super) fn refresh_known_data_imports(&mut self) -> Result<(), VmError> {
        for module in self.core.modules.loaded_modules() {
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
            let thunk = module.base + import.offset;
            let thunk_binding = self.core.hooks.import_binding_for_thunk(thunk).cloned();
            let thunk_value = self.read_pointer_value(thunk)?;
            let (has_resolved_target, owner_name) = {
                let owner = self.core.modules.get_by_address(thunk_value);
                (
                    self.core.hooks.bound_lookup(thunk_value).is_some()
                        || self
                            .core
                            .hooks
                            .observed_real_export_for_address(thunk_value)
                            .is_some(),
                    owner.map(|o| o.name.clone()),
                )
            };
            let unresolved_import = thunk_value == 0 || !has_resolved_target;
            if unresolved_import {
                // Permissive synthetic stubs without hook definitions are
                // intentionally allowed and should only report unsupported when
                // the guest actually calls them.
                let target_lower = import.dll.to_ascii_lowercase();
                let reason = if thunk_value == 0 {
                    "import thunk unresolved"
                } else if aliased_host_module(&target_lower).is_none()
                    && contract_hook_family(&target_lower).is_none()
                    && target_lower.starts_with("api-ms-win-")
                {
                    "contract family unmapped"
                } else {
                    "missing bound import target"
                };
                let target_module = thunk_binding
                    .as_ref()
                    .map(|binding| binding.requested_module.as_str())
                    .unwrap_or(&import.dll);
                let target_function = thunk_binding
                    .as_ref()
                    .map(|binding| binding.requested_function.as_str())
                    .unwrap_or(&import.function);
                let resolved_module_owned = thunk_binding
                    .as_ref()
                    .map(|binding| binding.resolved_module.clone())
                    .or(owner_name.clone());
                let resolved_function_owned = thunk_binding
                    .as_ref()
                    .map(|binding| binding.resolved_function.clone());
                self.log_unsupported_import(
                    module,
                    target_module,
                    target_function,
                    thunk,
                    reason,
                    resolved_module_owned.as_deref(),
                    resolved_function_owned.as_deref(),
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn write_u16(&mut self, address: u64, value: u16) -> Result<(), VmError> {
        self.core
            .modules
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
