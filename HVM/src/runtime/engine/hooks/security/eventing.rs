use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_eventing_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("api-ms-win-eventing-controller-l1-1-0.dll", "EventAccessQuery")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "EventAccessRemove")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "EventAccessControl")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "StartTraceA")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "StartTraceW")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "ControlTraceA")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "ControlTraceW")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "StopTraceA")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "StopTraceW")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "QueryAllTracesA")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "QueryAllTracesW")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "TraceSetInformation")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "EnableTraceEx2")
            | ("api-ms-win-eventing-controller-l1-1-0.dll", "EnumerateTraceGuidsEx")
            | ("api-ms-win-eventing-consumer-l1-1-0.dll", "OpenTraceA")
            | ("api-ms-win-eventing-consumer-l1-1-0.dll", "OpenTraceW")
            | ("api-ms-win-eventing-consumer-l1-1-0.dll", "ProcessTrace")
            | ("api-ms-win-eventing-consumer-l1-1-0.dll", "CloseTrace") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match function {
                "EventAccessQuery" => {
                    if ctx.raw(1) != 0 {
                        self.write_pointer_value(ctx.raw(1), 0)?;
                    }
                    if ctx.raw(2) != 0 {
                        self.write_u32(ctx.raw(2), 0)?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                "EventAccessRemove" | "EventAccessControl" => Ok(ERROR_SUCCESS),
                "StartTraceA" => {
                    let _ = self.read_c_string_from_memory(ctx.raw(1))?;
                    self.start_etw_trace(ctx.raw(0))
                }
                "StartTraceW" => {
                    let _ = self.read_wide_string_from_memory(ctx.raw(1))?;
                    self.start_etw_trace(ctx.raw(0))
                }
                "ControlTraceA" => {
                    let _ = self.read_c_string_from_memory(ctx.raw(1))?;
                    Ok(self.control_etw_trace(ctx.raw(0)))
                }
                "ControlTraceW" => {
                    let _ = self.read_wide_string_from_memory(ctx.raw(1))?;
                    Ok(self.control_etw_trace(ctx.raw(0)))
                }
                "StopTraceA" => {
                    let _ = self.read_c_string_from_memory(ctx.raw(1))?;
                    Ok(self.control_etw_trace(ctx.raw(0)))
                }
                "StopTraceW" => {
                    let _ = self.read_wide_string_from_memory(ctx.raw(1))?;
                    Ok(self.control_etw_trace(ctx.raw(0)))
                }
                "QueryAllTracesA" | "QueryAllTracesW" => {
                    if ctx.raw(2) != 0 {
                        self.write_u32(ctx.raw(2), 0)?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                "TraceSetInformation" => Ok(ERROR_SUCCESS),
                "EnableTraceEx2" => Ok(ERROR_SUCCESS),
                "EnumerateTraceGuidsEx" => {
                    if ctx.raw(3) != 0 && ctx.raw(4) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(3), &vec![0u8; ctx.raw(4) as usize])?;
                    }
                    if ctx.raw(5) != 0 {
                        self.write_u32(ctx.raw(5), 0)?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                "OpenTraceA" | "OpenTraceW" => self.open_etw_trace(ctx.raw(0)),
                "ProcessTrace" => self.process_etw_traces(ctx.raw(0), ctx.raw(1) as usize),
                "CloseTrace" => Ok(self.close_etw_trace(ctx.raw(0))),
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }

    pub(in crate::runtime::engine) fn dispatch_advapi32_eventing_forward(
        &mut self,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let target_module = match function {
            "EventAccessQuery"
            | "EventAccessRemove"
            | "EventAccessControl"
            | "StartTraceA"
            | "StartTraceW"
            | "ControlTraceA"
            | "ControlTraceW"
            | "StopTraceA"
            | "StopTraceW"
            | "QueryAllTracesA"
            | "QueryAllTracesW"
            | "TraceSetInformation"
            | "EnableTraceEx2"
            | "EnumerateTraceGuidsEx" => "api-ms-win-eventing-controller-l1-1-0.dll",
            "OpenTraceA" | "OpenTraceW" | "ProcessTrace" | "CloseTrace" => {
                "api-ms-win-eventing-consumer-l1-1-0.dll"
            }
            _ => return None,
        };
        self.dispatch_eventing_hook(target_module, function, ctx)
    }

    fn start_etw_trace(&mut self, trace_handle_ptr: u64) -> Result<u64, VmError> {
        if trace_handle_ptr == 0 {
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let handle = self.allocate_object_handle();
        self.handles.etw_trace_handles.insert(handle);
        self.write_pointer_value(trace_handle_ptr, handle as u64)?;
        Ok(ERROR_SUCCESS)
    }

    fn control_etw_trace(&mut self, trace_handle: u64) -> u64 {
        if trace_handle != 0 {
            self.handles
                .etw_trace_handles
                .remove(&(trace_handle as u32));
        }
        ERROR_SUCCESS
    }

    fn open_etw_trace(&mut self, logfile_ptr: u64) -> Result<u64, VmError> {
        if logfile_ptr == 0 {
            return Ok(u64::MAX);
        }
        let handle = self.allocate_object_handle();
        self.handles.etw_trace_handles.insert(handle);
        Ok(handle as u64)
    }

    fn process_etw_traces(
        &mut self,
        trace_handle_array: u64,
        trace_handle_count: usize,
    ) -> Result<u64, VmError> {
        if trace_handle_count == 0 {
            return Ok(ERROR_SUCCESS);
        }
        if trace_handle_array == 0 {
            return Ok(ERROR_INVALID_PARAMETER);
        }
        for index in 0..trace_handle_count {
            let address = trace_handle_array + (index as u64 * 8);
            let handle = u64::from_le_bytes(
                self.read_bytes_from_memory(address, 8)?
                    .try_into()
                    .expect("trace handle width should be 8 bytes"),
            );
            if handle != 0 && !self.handles.etw_trace_handles.contains(&(handle as u32)) {
                return Ok(ERROR_INVALID_HANDLE);
            }
        }
        Ok(ERROR_SUCCESS)
    }

    fn close_etw_trace(&mut self, trace_handle: u64) -> u64 {
        if trace_handle == 0 {
            return ERROR_INVALID_HANDLE;
        }
        if self
            .handles
            .etw_trace_handles
            .remove(&(trace_handle as u32))
        {
            ERROR_SUCCESS
        } else {
            ERROR_INVALID_HANDLE
        }
    }
}
