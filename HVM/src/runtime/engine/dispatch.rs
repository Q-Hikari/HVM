//! Dispatch methods for bound stub execution through Unicorn engine.
//!
//! Contains VirtualExecutionEngine methods for dispatching bound API stubs,
//! handling protected fetches, and classifying address types.

use super::VirtualExecutionEngine;
use super::*;
use crate::error::VmError;
use crate::runtime::api_logger::{ApiExecutionContext, ApiStackWord};
use crate::runtime::engine::abi::adapter::select_adapter;
use crate::runtime::engine::native_trace_types::PendingProtectedFetchAction;
use crate::runtime::engine::protected_fetch::{
    decide_protected_fetch, ProtectedFetchBinding, ProtectedFetchContext, ProtectedFetchDecision,
    ProtectedFetchModuleState,
};
use crate::runtime::unicorn::{UcEngine, UnicornApi};

impl VirtualExecutionEngine {
    pub(super) fn maybe_log_observed_real_export_call(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        address: u64,
    ) -> Result<bool, VmError> {
        let Some((target_module, target_function)) = self
            .core
            .hooks
            .observed_real_export_for_address(address)
            .map(|(module, function)| (module.to_string(), function.to_string()))
        else {
            return Ok(false);
        };
        let unicorn = unsafe { api.bind(uc) };
        let (sp_reg, ptr_size) = if self.core.arch.is_x86() {
            (UC_X86_REG_ESP, 4usize)
        } else {
            (UC_X86_REG_RSP, 8usize)
        };
        let sp = unicorn
            .reg_read(sp_reg)
            .map_err(|detail| VmError::NativeExecution {
                op: "uc_reg_read(sp)",
                detail,
            })?;
        let return_to = unicorn
            .mem_read(sp, ptr_size)
            .map(|bytes| {
                if ptr_size == 4 {
                    u32::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 4])) as u64
                } else {
                    u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 8]))
                }
            })
            .unwrap_or(0);
        self.log_real_export_call(address, return_to, &target_module, &target_function)?;
        Ok(true)
    }

    /// Dispatches one already-bound synthetic export stub through the live runtime state.
    pub fn dispatch_bound_stub(&mut self, address: u64, args: &[u64]) -> Result<u64, VmError> {
        let Some(signature) = self.core.hooks.signature_for_address(address).cloned() else {
            if let Some((module, function)) = self.core.hooks.binding_for_address(address) {
                let module = module.to_string();
                let function = function.to_string();
                let _ = self.log_unsupported_bound_stub(
                    address,
                    &module,
                    &function,
                    "missing hook definition",
                );
                if self.core.config.exit_on_unsupported_hook {
                    self.core.stop_reason = Some(RunStopReason::UnsupportedHook);
                    return Err(VmError::NativeExecution {
                        op: "dispatch",
                        detail: format!("exit_on_unsupported: no hook for {}!{}", module, function),
                    });
                }
                if self.strict_unknown_api_policy() {
                    return Err(VmError::NativeExecution {
                        op: "dispatch",
                        detail: format!(
                            "unknown_api_policy={} rejected undefined hook {}!{} at 0x{address:X}",
                            self.core.config.unknown_api_policy, module, function
                        ),
                    });
                }
                return Ok(0);
            }
            return Err(VmError::NativeExecution {
                op: "dispatch",
                detail: format!("address 0x{address:X} is not a bound hook stub"),
            });
        };

        self.dispatch_bound_stub_with_signature(&signature, address, None, args)
            .map(|hv| hv.into_raw(&self.core.arch))
    }

    pub(super) fn dispatch_unicorn_bound_stub(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        address: u64,
    ) -> Result<bool, VmError> {
        if self.maybe_log_observed_real_export_call(api, uc, address)? {
            return Ok(false);
        }
        let unicorn = unsafe { api.bind(uc) };
        let Some(bound) = self.core.hooks.bound_lookup(address) else {
            return Ok(false);
        };
        let bound_module = bound.module.to_string();
        let bound_function = bound.function.to_string();
        let signature = bound.signature.cloned();

        let Some(signature) = signature else {
            if let Some(owner) = self.core.modules.get_by_address(address) {
                if owner.allow_execution && !owner.synthetic {
                    let unicorn = unsafe { api.bind(uc) };
                    let (sp_reg, ptr_size) = if self.core.arch.is_x86() {
                        (UC_X86_REG_ESP, 4usize)
                    } else {
                        (UC_X86_REG_RSP, 8usize)
                    };
                    let sp =
                        unicorn
                            .reg_read(sp_reg)
                            .map_err(|detail| VmError::NativeExecution {
                                op: "uc_reg_read(sp)",
                                detail,
                            })?;
                    let return_to = unicorn
                        .mem_read(sp, ptr_size)
                        .map(|bytes| {
                            if ptr_size == 4 {
                                u32::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 4]))
                                    as u64
                            } else {
                                u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 8]))
                            }
                        })
                        .unwrap_or(0);
                    self.log_real_export_call(address, return_to, &bound_module, &bound_function)?;
                    return Ok(false);
                }
            }
            let _ = self.log_unsupported_bound_stub(
                address,
                &bound_module,
                &bound_function,
                "missing hook signature",
            );
            if self.core.config.exit_on_unsupported_hook {
                self.core.stop_reason = Some(RunStopReason::UnsupportedHook);
                return Err(VmError::NativeExecution {
                    op: "dispatch",
                    detail: format!(
                        "exit_on_unsupported: missing hook signature for {}!{}",
                        bound_module, bound_function
                    ),
                });
            }
            let (sp_reg, pc_reg, rv_reg, ptr_size) = if self.core.arch.is_x86() {
                (UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, 4usize)
            } else {
                (UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_RAX, 8usize)
            };
            let sp = unicorn
                .reg_read(sp_reg)
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_reg_read(sp)",
                    detail,
                })?;
            let ret_bytes =
                unicorn
                    .mem_read(sp, ptr_size)
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_mem_read(stack)",
                        detail,
                    })?;
            let ret_addr = if ptr_size == 4 {
                u32::from_le_bytes(ret_bytes.as_slice().try_into().unwrap_or([0; 4])) as u64
            } else {
                u64::from_le_bytes(ret_bytes.as_slice().try_into().unwrap_or([0; 8]))
            };
            if ret_addr <= 0x10000 {
                return Ok(false);
            }
            unicorn
                .reg_write(rv_reg, 0)
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_reg_write(rv)",
                    detail,
                })?;
            unicorn
                .reg_write(sp_reg, sp.wrapping_add(ptr_size as u64))
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_reg_write(sp)",
                    detail,
                })?;
            unicorn
                .reg_write(pc_reg, ret_addr)
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_reg_write(pc)",
                    detail,
                })?;
            return Ok(true);
        };

        // Capture x86 non-volatile registers before dispatch (engine-layer concern,
        // not part of the ABI adapter).
        let saved_x86_nonvolatile =
            if self.core.arch.is_x86() {
                let ebx = unicorn.reg_read(UC_X86_REG_EBX).map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(ebx)",
                        detail,
                    }
                })?;
                let ebp = unicorn.reg_read(UC_X86_REG_EBP).map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(ebp)",
                        detail,
                    }
                })?;
                let esi = unicorn.reg_read(UC_X86_REG_ESI).map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(esi)",
                        detail,
                    }
                })?;
                let edi = unicorn.reg_read(UC_X86_REG_EDI).map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(edi)",
                        detail,
                    }
                })?;
                // HVM DEBUG: track EDI=0xE004 propagation
                if edi == 0xE004 {
                    let tid = self.core.scheduler.current_tid().unwrap_or(0);
                    eprintln!(
                        "[EDI-TRACE] SAVE edi=0xE004 tid={} pc=0x{:X} fn={}!{}",
                        tid, address, bound_module, bound_function
                    );
                }
                Some((ebx, ebp, esi, edi))
            } else {
                None
            };

        // Use the ABI adapter to capture the call frame.
        let adapter = select_adapter(&self.core.arch, &signature.abi);
        let frame = {
            let mut reg_read = |regid: i32| -> Result<u64, String> { unicorn.reg_read(regid) };
            let mut mem_read = |addr: u64, size: usize| -> Result<Vec<u8>, String> {
                unicorn.mem_read(addr, size)
            };
            adapter.capture_call_frame(&self.core.arch, &signature, &mut reg_read, &mut mem_read)?
        };

        let return_address = frame.return_address.unwrap_or(0);
        let stack_pointer = frame.stack_pointer;
        let args: Vec<u64> = frame.args.to_vec();

        self.dispatch.api_log_context_override = if self.core.config.api_log_include_context {
            let pointer_size = if self.core.arch.is_x86() {
                4usize
            } else {
                8usize
            };
            let stack_words = (0..self.core.config.api_log_stack_words)
                .map(|index| {
                    let address = stack_pointer.saturating_add((index * pointer_size) as u64);
                    let value = unicorn
                        .mem_read(address, pointer_size)
                        .ok()
                        .map(|bytes| {
                            if pointer_size == 4 {
                                let arr: [u8; 4] = bytes.as_slice().try_into().ok()?;
                                Some(u32::from_le_bytes(arr) as u64)
                            } else {
                                let arr: [u8; 8] = bytes.as_slice().try_into().ok()?;
                                Some(u64::from_le_bytes(arr))
                            }
                        })
                        .flatten();
                    ApiStackWord {
                        address,
                        value,
                        value_ref: value
                            .filter(|value| *value != 0)
                            .map(|value| self.address_ref(value)),
                        read_error: value.is_none().then(|| "uc_mem_read(stack)".to_string()),
                    }
                })
                .collect::<Vec<_>>();
            // Reuse already-read non-volatile registers to reduce FFI overhead
            let (saved_ebx, saved_ebp, saved_esi, saved_edi) =
                saved_x86_nonvolatile.unwrap_or((0, 0, 0, 0));
            Some(if self.core.arch.is_x86() {
                let flags = unicorn.reg_read(UC_X86_REG_EFLAGS).unwrap_or(0);
                ApiExecutionContext {
                    ip: address,
                    sp: stack_pointer,
                    bp: saved_ebp,
                    ax: unicorn.reg_read(UC_X86_REG_EAX).unwrap_or(0),
                    bx: saved_ebx,
                    cx: unicorn.reg_read(UC_X86_REG_ECX).unwrap_or(0),
                    dx: unicorn.reg_read(UC_X86_REG_EDX).unwrap_or(0),
                    si: saved_esi,
                    di: saved_edi,
                    flags,
                    direction_flag: ((flags >> 10) & 1) != 0,
                    stack_words,
                }
            } else {
                let flags = unicorn.reg_read(UC_X86_REG_RFLAGS).unwrap_or(0);
                ApiExecutionContext {
                    ip: if frame.instruction_pointer != 0 {
                        frame.instruction_pointer
                    } else {
                        address
                    },
                    sp: stack_pointer,
                    bp: unicorn.reg_read(UC_X86_REG_RBP).unwrap_or(0),
                    ax: unicorn.reg_read(UC_X86_REG_RAX).unwrap_or(0),
                    bx: unicorn.reg_read(UC_X86_REG_RBX).unwrap_or(0),
                    cx: unicorn.reg_read(UC_X86_REG_RCX).unwrap_or(0),
                    dx: unicorn.reg_read(UC_X86_REG_RDX).unwrap_or(0),
                    si: unicorn.reg_read(UC_X86_REG_RSI).unwrap_or(0),
                    di: unicorn.reg_read(UC_X86_REG_RDI).unwrap_or(0),
                    flags,
                    direction_flag: ((flags >> 10) & 1) != 0,
                    stack_words,
                }
            })
        } else {
            None
        };

        let hook_unicorn_context = HookUnicornContext {
            engine: self as *mut Self,
            api: std::ptr::from_ref(api),
            uc,
        };
        let retval = ACTIVE_HOOK_UNICORN_CONTEXT.with(|slot| {
            let previous = slot.replace(Some(hook_unicorn_context));
            let result = self.dispatch_bound_stub_with_signature(
                &signature,
                address,
                Some(return_address),
                &args,
            );
            slot.set(previous);
            result
        })?;
        self.dispatch.api_log_context_override = None;

        if let Some(restore) = self.exception.pending_context_restore.take() {
            let _ = self.dispatch.take_hook_return_override();
            self.dispatch.reset_api_flow_control();
            self.restore_unicorn_thread_registers(api, uc, &restore.registers)?;
            if self.core.arch.is_x86() {
                self.restore_unicorn_x86_segments_from_context(api, uc, restore.context_address)?;
            }
        } else {
            let current_thread_state = self
                .core
                .scheduler
                .current_tid()
                .and_then(|tid| self.core.scheduler.thread_state(tid));
            let yielded_blocking_thread = current_thread_state != Some("running");
            let yield_requested = self.dispatch.thread_yield_requested();
            let preserve_blocked_api_frame = self.dispatch.preserve_blocked_api_frame
                && yield_requested
                && yielded_blocking_thread;
            if self.dispatch.api_return_deferred() || preserve_blocked_api_frame {
                let _ = self.dispatch.take_hook_return_override();
            } else {
                let hook_return_override = self.dispatch.take_hook_return_override();
                let raw_retval = hook_return_override
                    .map(|override_value| override_value.raw_retval)
                    .unwrap_or_else(|| retval.into_raw(&self.core.arch));

                // Write return value via the ABI adapter.
                {
                    let mut reg_write = |regid: i32, value: u64| -> Result<(), String> {
                        unicorn.reg_write(regid, value)
                    };
                    adapter.write_return_value(&self.core.arch, raw_retval, &mut reg_write)?;
                }

                // Special case: VerSetConditionMask returns 64-bit in EDX:EAX on x86.
                if self.core.arch.is_x86() && signature.function == "VerSetConditionMask" {
                    unicorn
                        .reg_write(UC_X86_REG_EDX, raw_retval >> 32)
                        .map_err(|detail| VmError::NativeExecution {
                            op: "uc_reg_write(edx)",
                            detail,
                        })?;
                }

                // Restore x86 non-volatile registers.
                if let Some((saved_ebx, saved_ebp, saved_esi, saved_edi)) = saved_x86_nonvolatile {
                    // HVM DEBUG: check if Unicorn EDI was modified during handler
                    let current_edi = unicorn.reg_read(UC_X86_REG_EDI).unwrap_or(0);
                    if current_edi != saved_edi {
                        let tid = self.core.scheduler.current_tid().unwrap_or(0);
                        eprintln!(
                            "[EDI-CORRUPT] EDI changed during handler! tid={} fn={}!{} saved=0x{:X} current=0x{:X}",
                            tid, bound_module, bound_function, saved_edi, current_edi
                        );
                    }
                    if saved_edi == 0xE004 {
                        let tid = self.core.scheduler.current_tid().unwrap_or(0);
                        eprintln!(
                            "[EDI-TRACE] RESTORE edi=0xE004 tid={} fn={}!{}",
                            tid, bound_module, bound_function
                        );
                    }
                    unicorn
                        .reg_write(UC_X86_REG_EBX, saved_ebx)
                        .map_err(|detail| VmError::NativeExecution {
                            op: "uc_reg_write(ebx)",
                            detail,
                        })?;
                    unicorn
                        .reg_write(UC_X86_REG_EBP, saved_ebp)
                        .map_err(|detail| VmError::NativeExecution {
                            op: "uc_reg_write(ebp)",
                            detail,
                        })?;
                    unicorn
                        .reg_write(UC_X86_REG_ESI, saved_esi)
                        .map_err(|detail| VmError::NativeExecution {
                            op: "uc_reg_write(esi)",
                            detail,
                        })?;
                    unicorn
                        .reg_write(UC_X86_REG_EDI, saved_edi)
                        .map_err(|detail| VmError::NativeExecution {
                            op: "uc_reg_write(edi)",
                            detail,
                        })?;
                }

                // Adjust stack pointer via the ABI adapter.
                let new_sp =
                    adapter.adjust_stack_after_call(&self.core.arch, &signature, stack_pointer);
                let (sp_reg, pc_reg) = if self.core.arch.is_x86() {
                    (UC_X86_REG_ESP, UC_X86_REG_EIP)
                } else {
                    (UC_X86_REG_RSP, UC_X86_REG_RIP)
                };
                unicorn
                    .reg_write(sp_reg, new_sp)
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_reg_write(sp)",
                        detail,
                    })?;
                let next_pc = if self.dispatch.force_native_return {
                    self.dispatch.force_native_return = false;
                    self.core.native_return_sentinel
                } else {
                    return_address
                };
                unicorn
                    .reg_write(pc_reg, next_pc)
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_reg_write(pc)",
                        detail,
                    })?;
                if let Some(override_value) = hook_return_override {
                    let flags_reg = if self.core.arch.is_x86() {
                        UC_X86_REG_EFLAGS
                    } else {
                        UC_X86_REG_RFLAGS
                    };
                    let current_flags =
                        unicorn
                            .reg_read(flags_reg)
                            .map_err(|detail| VmError::NativeExecution {
                                op: "uc_reg_read(flags)",
                                detail,
                            })?;
                    let new_flags =
                        (current_flags & !override_value.flags_mask) | override_value.flags_value;
                    unicorn.reg_write(flags_reg, new_flags).map_err(|detail| {
                        VmError::NativeExecution {
                            op: "uc_reg_write(flags)",
                            detail,
                        }
                    })?;
                }
            }
        }
        let current_thread_state = self
            .core
            .scheduler
            .current_tid()
            .and_then(|tid| self.core.scheduler.thread_state(tid));
        let yielded_blocking_thread = current_thread_state != Some("running");
        let yield_requested = self.dispatch.thread_yield_requested();
        if yield_requested || yielded_blocking_thread {
            let _ = self.log_unicorn_api_yield_event(
                address,
                signature.function,
                yield_requested,
                yielded_blocking_thread,
            );
            let _ = unicorn.emu_stop();
        }
        // When defer_api_return is true, registers have already been rewritten
        // (for example to jump into a guest callback). Stop the current
        // emu_start slice so the outer loop can restart Unicorn from the new
        // PC instead of executing the original bound-stub bytes one more time.
        if self.dispatch.api_return_deferred() {
            let _ = unicorn.emu_stop();
        }
        Ok(true)
    }

    #[allow(dead_code)]
    pub(super) fn dispatch_unicorn_non_executable_module_address(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        address: u64,
        pending_protected_fetch: &mut Option<PendingProtectedFetchAction>,
    ) -> Result<bool, VmError> {
        let Some(module) = self.core.modules.get_by_address(address) else {
            return Ok(false);
        };
        if module.synthetic || module.allow_execution {
            return Ok(false);
        }
        match self.classify_protected_fetch(api, uc, address) {
            ProtectedFetchDecision::DispatchBound { address } => {
                *pending_protected_fetch =
                    Some(PendingProtectedFetchAction::DispatchBound { address });
                Ok(true)
            }
            ProtectedFetchDecision::SimulateReturn { address, binding } => {
                *pending_protected_fetch =
                    Some(PendingProtectedFetchAction::SimulateReturn { address, binding });
                Ok(true)
            }
            ProtectedFetchDecision::StaleFetchIgnore => Ok(true),
            ProtectedFetchDecision::RaiseFault => Ok(false),
        }
    }

    pub(super) fn handle_pending_protected_fetch(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        action: PendingProtectedFetchAction,
    ) -> Result<bool, VmError> {
        let unicorn = unsafe { api.bind(uc) };
        match action {
            PendingProtectedFetchAction::DispatchBound { address } => {
                self.dispatch_unicorn_bound_stub(api, uc, address)
            }
            PendingProtectedFetchAction::SimulateReturn { address, binding } => {
                if let Some((module_name, function_name)) = binding.as_ref() {
                    let _ = self.log_unsupported_bound_stub(
                        address,
                        module_name,
                        function_name,
                        "missing hook definition for real export",
                    );
                    if self.core.config.exit_on_unsupported_hook {
                        self.core.stop_reason = Some(RunStopReason::UnsupportedHook);
                        return Err(VmError::NativeExecution {
                            op: "dispatch",
                            detail: format!(
                                "exit_on_unsupported: no hook for real export {}!{}",
                                module_name, function_name
                            ),
                        });
                    }
                }

                let (sp_reg, pc_reg, rv_reg, ptr_size) = if self.core.arch.is_x86() {
                    (UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, 4usize)
                } else {
                    (UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_RAX, 8usize)
                };
                let sp = unicorn
                    .reg_read(sp_reg)
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_reg_read(sp)",
                        detail,
                    })?;
                let ret_bytes =
                    unicorn
                        .mem_read(sp, ptr_size)
                        .map_err(|detail| VmError::NativeExecution {
                            op: "uc_mem_read(stack)",
                            detail,
                        })?;
                let ret_addr = if ptr_size == 4 {
                    u32::from_le_bytes(ret_bytes.as_slice().try_into().unwrap_or([0; 4])) as u64
                } else {
                    u64::from_le_bytes(ret_bytes.as_slice().try_into().unwrap_or([0; 8]))
                };
                if ret_addr <= 0x10000 {
                    return Err(VmError::NativeExecution {
                        op: "dispatch",
                        detail: format!(
                            "protected fetch at 0x{address:X} has invalid return address 0x{ret_addr:X}"
                        ),
                    });
                }

                unicorn
                    .reg_write(rv_reg, 0)
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_reg_write(rv)",
                        detail,
                    })?;
                unicorn
                    .reg_write(sp_reg, sp.wrapping_add(ptr_size as u64))
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_reg_write(sp)",
                        detail,
                    })?;
                unicorn
                    .reg_write(pc_reg, ret_addr)
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_reg_write(pc)",
                        detail,
                    })?;
                Ok(true)
            }
        }
    }

    pub(super) fn classify_protected_fetch(
        &self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault_address: u64,
    ) -> ProtectedFetchDecision {
        let unicorn = unsafe { api.bind(uc) };
        let current_pc = unicorn
            .reg_read(self.instruction_pointer_register())
            .unwrap_or(fault_address);
        let current_pc_module_base = self
            .core
            .modules
            .get_by_address(current_pc)
            .map(|module| module.base);
        let fault_module = self
            .core
            .modules
            .get_by_address(fault_address)
            .map(|module| ProtectedFetchModuleState {
                base: module.base,
                synthetic: module.synthetic,
                allow_execution: module.allow_execution,
            });
        let binding =
            self.core
                .hooks
                .binding_for_address(fault_address)
                .map(|(module, function)| ProtectedFetchBinding {
                    module: module.to_string(),
                    function: function.to_string(),
                });
        let has_definition = self
            .core
            .hooks
            .signature_for_address(fault_address)
            .is_some();
        decide_protected_fetch(&ProtectedFetchContext {
            current_pc,
            fault_address,
            current_pc_module_base,
            fault_module,
            binding,
            has_definition,
        })
    }
}
