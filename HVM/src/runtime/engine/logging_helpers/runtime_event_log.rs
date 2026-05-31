use super::*;

impl VirtualExecutionEngine {
    pub fn log_seh_dispatch(
        &mut self,
        fault: UnicornFault,
        registration: u64,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("access".to_string(), json!(fault.access.as_str()));
        if let Some(exception_code) = fault.exception_code {
            fields.insert("exception_code".to_string(), json!(exception_code));
        }
        fields.insert("pc".to_string(), json!(fault.pc));
        fields.insert("address".to_string(), json!(fault.address));
        fields.insert("size".to_string(), json!(fault.size));
        fields.insert("registration".to_string(), json!(registration));
        self.add_address_ref_fields(&mut fields, "pc", fault.pc);
        self.add_address_ref_fields(&mut fields, "address", fault.address);
        self.add_address_ref_fields(&mut fields, "registration", registration);
        self.log_runtime_event_immediate("SEH_DISPATCH", fields)
    }

    pub fn log_seh_handler(
        &mut self,
        registration: u64,
        handler: u64,
        disposition: u32,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("registration".to_string(), json!(registration));
        fields.insert("handler".to_string(), json!(handler));
        fields.insert("disposition".to_string(), json!(disposition));
        self.add_address_ref_fields(&mut fields, "registration", registration);
        self.add_address_ref_fields(&mut fields, "handler", handler);
        self.log_runtime_event_immediate("SEH_HANDLER", fields)
    }

    pub fn log_seh_resume(
        &mut self,
        context_record: u64,
        registers: &RegisterFile,
    ) -> Result<(), VmError> {
        let pc = if self.core.arch.is_x86() {
            registers.eip
        } else {
            registers.rip
        };
        let mut fields = Map::new();
        fields.insert("context_record".to_string(), json!(context_record));
        fields.insert("pc".to_string(), json!(pc));
        fields.insert("registers".to_string(), Self::register_map_value(registers));
        self.add_address_ref_fields(&mut fields, "pc", pc);
        self.add_address_ref_fields(&mut fields, "context", context_record);
        self.log_runtime_event_immediate("SEH_RESUME", fields)
    }

    pub fn log_x64_seh_dispatch(
        &mut self,
        fault: UnicornFault,
        exception_record: u64,
        context_record: u64,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("access".to_string(), json!(fault.access.as_str()));
        if let Some(exception_code) = fault.exception_code {
            fields.insert("exception_code".to_string(), json!(exception_code));
        }
        fields.insert("pc".to_string(), json!(fault.pc));
        fields.insert("address".to_string(), json!(fault.address));
        fields.insert("size".to_string(), json!(fault.size));
        fields.insert("exception_record".to_string(), json!(exception_record));
        fields.insert("context_record".to_string(), json!(context_record));
        self.add_address_ref_fields(&mut fields, "pc", fault.pc);
        self.add_address_ref_fields(&mut fields, "address", fault.address);
        self.add_address_ref_fields(&mut fields, "exception", exception_record);
        self.add_address_ref_fields(&mut fields, "context", context_record);
        self.log_runtime_event_immediate("SEH_X64_DISPATCH", fields)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_x64_seh_frame(
        &mut self,
        control_pc: u64,
        function_entry: u64,
        unwind_info: u64,
        establisher_frame: u64,
        handler: Option<u64>,
        handler_data: Option<u64>,
        flags: u8,
        leaf: bool,
        caller_pc: u64,
        caller_sp: u64,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("control_pc".to_string(), json!(control_pc));
        fields.insert("function_entry".to_string(), json!(function_entry));
        fields.insert("unwind_info".to_string(), json!(unwind_info));
        fields.insert("establisher_frame".to_string(), json!(establisher_frame));
        fields.insert("handler".to_string(), json!(handler.unwrap_or(0)));
        fields.insert("handler_data".to_string(), json!(handler_data.unwrap_or(0)));
        fields.insert("flags".to_string(), json!(flags));
        fields.insert("leaf".to_string(), json!(leaf));
        fields.insert("caller_pc".to_string(), json!(caller_pc));
        fields.insert("caller_sp".to_string(), json!(caller_sp));
        self.add_address_ref_fields(&mut fields, "control_pc", control_pc);
        self.add_address_ref_fields(&mut fields, "function_entry", function_entry);
        self.add_address_ref_fields(&mut fields, "unwind_info", unwind_info);
        self.add_address_ref_fields(&mut fields, "establisher_frame", establisher_frame);
        self.add_address_ref_fields(&mut fields, "handler", handler.unwrap_or(0));
        self.add_address_ref_fields(&mut fields, "handler_data", handler_data.unwrap_or(0));
        self.add_address_ref_fields(&mut fields, "caller_pc", caller_pc);
        self.add_address_ref_fields(&mut fields, "caller_sp", caller_sp);
        self.log_runtime_event_immediate("SEH_X64_FRAME", fields)
    }

    pub fn log_x64_seh_unhandled(
        &mut self,
        exception_code: u32,
        control_pc: u64,
        establisher_frame: u64,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("exception_code".to_string(), json!(exception_code));
        fields.insert(
            "exception_text".to_string(),
            json!(Self::format_exception_code_for_log(exception_code)),
        );
        fields.insert("control_pc".to_string(), json!(control_pc));
        fields.insert("establisher_frame".to_string(), json!(establisher_frame));
        self.add_address_ref_fields(&mut fields, "control_pc", control_pc);
        self.add_address_ref_fields(&mut fields, "establisher_frame", establisher_frame);
        self.log_runtime_event_immediate("SEH_X64_UNHANDLED", fields)
    }

    pub fn log_x64_seh_unwind_suspicious(
        &mut self,
        control_pc: u64,
        establisher_frame: u64,
        register: &str,
        value: u64,
        caller_context: &RegisterFile,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("control_pc".to_string(), json!(control_pc));
        fields.insert("establisher_frame".to_string(), json!(establisher_frame));
        fields.insert("register".to_string(), json!(register));
        fields.insert("value".to_string(), json!(value));
        self.add_address_ref_fields(&mut fields, "control_pc", control_pc);
        self.add_address_ref_fields(&mut fields, "establisher_frame", establisher_frame);
        // Include key restored registers for context
        for name in &[
            "rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15", "rsp", "rip",
        ] {
            let v = caller_context.get(name);
            if v != 0 {
                fields.insert(format!("caller_{name}"), json!(v));
            }
        }
        self.log_runtime_event_immediate("SEH_UNWIND_SUSPICIOUS", fields)
    }

    pub fn log_module_event(
        &mut self,
        marker: &str,
        module: &ModuleRecord,
        source: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("source".to_string(), json!(source));
        fields.insert("module".to_string(), json!(module.name.clone()));
        fields.insert("base".to_string(), json!(module.base));
        fields.insert("size".to_string(), json!(module.size));
        fields.insert("entrypoint".to_string(), json!(module.entrypoint));
        fields.insert("synthetic".to_string(), json!(module.synthetic));
        if let Some(path) = module.path.as_ref() {
            fields.insert(
                "path".to_string(),
                json!(path.to_string_lossy().to_string()),
            );
        }
        self.log_runtime_event(marker, fields)
    }

    pub fn log_module_notification(
        &mut self,
        module: &ModuleRecord,
        reason: u64,
        phase: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("module".to_string(), json!(module.name.clone()));
        fields.insert("base".to_string(), json!(module.base));
        fields.insert("entrypoint".to_string(), json!(module.entrypoint));
        fields.insert("reason".to_string(), json!(Self::dll_reason_name(reason)));
        fields.insert("phase".to_string(), json!(phase));
        fields.insert("routine".to_string(), json!("DllMain"));
        fields.insert("synthetic".to_string(), json!(module.synthetic));
        if let Some(path) = module.path.as_ref() {
            fields.insert(
                "path".to_string(),
                json!(path.to_string_lossy().to_string()),
            );
        }
        self.add_address_ref_fields(&mut fields, "entrypoint", module.entrypoint);
        self.log_runtime_event("DLL_NOTIFICATION", fields)
    }

    pub fn log_entry_invoke(
        &mut self,
        module: &ModuleRecord,
        address: u64,
        arguments: &[u64],
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert(
            "invocation".to_string(),
            json!(match self.core.entry_invocation {
                EntryInvocation::NativeEntrypoint => "native_entrypoint",
                EntryInvocation::Export => "export",
            }),
        );
        fields.insert("module".to_string(), json!(module.name.clone()));
        fields.insert("base".to_string(), json!(module.base));
        fields.insert("address".to_string(), json!(address));
        fields.insert("argc".to_string(), json!(arguments.len()));
        fields.insert("args".to_string(), json!(arguments));
        if let Some(path) = module.path.as_ref() {
            fields.insert(
                "path".to_string(),
                json!(path.to_string_lossy().to_string()),
            );
        }
        if let Some(export) = self.core.config.entry_export.as_deref() {
            fields.insert("export".to_string(), json!(export));
        }
        if let Some(ordinal) = self.core.config.entry_ordinal {
            fields.insert("ordinal".to_string(), json!(ordinal));
        }
        self.add_address_ref_fields(&mut fields, "address", address);
        self.log_runtime_event("ENTRY_INVOKE", fields)
    }

    pub fn log_tls_callback_event(
        &mut self,
        module: &ModuleRecord,
        callback: u64,
        reason: u64,
        phase: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("module".to_string(), json!(module.name.clone()));
        fields.insert("base".to_string(), json!(module.base));
        fields.insert("callback".to_string(), json!(callback));
        fields.insert("reason".to_string(), json!(Self::dll_reason_name(reason)));
        fields.insert("phase".to_string(), json!(phase));
        fields.insert("synthetic".to_string(), json!(module.synthetic));
        self.add_address_ref_fields(&mut fields, "callback", callback);
        self.log_runtime_event("TLS_CALLBACK", fields)
    }

    pub fn log_thread_event(
        &mut self,
        marker: &str,
        tid: u32,
        handle: u32,
        start_address: u64,
        parameter: u64,
        state: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("thread_tid".to_string(), json!(tid));
        fields.insert("thread_handle".to_string(), json!(handle));
        fields.insert("start_address".to_string(), json!(start_address));
        fields.insert("parameter".to_string(), json!(parameter));
        fields.insert("state".to_string(), json!(state));
        self.log_runtime_event(marker, fields)
    }

    pub fn log_scheduler_event(
        &mut self,
        marker: &str,
        tid: Option<u32>,
        budget: Option<u64>,
        consumed: Option<u64>,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        if let Some(tid) = tid {
            fields.insert("thread_tid".to_string(), json!(tid));
            if let Some(thread) = self.core.scheduler.thread_snapshot(tid) {
                fields.insert("thread_handle".to_string(), json!(thread.handle));
                fields.insert("state".to_string(), json!(thread.state));
                fields.insert("start_address".to_string(), json!(thread.start_address));
                fields.insert(
                    "thread_instruction_count".to_string(),
                    json!(thread.instruction_count),
                );
                fields.insert("wake_tick".to_string(), json!(thread.wake_tick));
            }
        }
        if let Some(budget) = budget {
            fields.insert("budget".to_string(), json!(budget));
        }
        if let Some(consumed) = consumed {
            fields.insert("consumed".to_string(), json!(consumed));
        }
        fields.insert(
            "ready_tids".to_string(),
            json!(self.core.scheduler.ready_thread_ids()),
        );
        fields.insert(
            "current_tid".to_string(),
            json!(self.core.scheduler.current_tid()),
        );
        self.log_runtime_event(marker, fields)
    }

    pub fn log_thread_yield_event(
        &mut self,
        reason: &str,
        sleep_ms: Option<u64>,
        defer_api_return: bool,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("reason".to_string(), json!(reason));
        fields.insert("defer_api_return".to_string(), json!(defer_api_return));
        if let Some(sleep_ms) = sleep_ms {
            fields.insert("sleep_ms".to_string(), json!(sleep_ms));
        }
        if let Some(tid) = self.core.scheduler.current_tid() {
            fields.insert("thread_tid".to_string(), json!(tid));
            if let Some(thread) = self.core.scheduler.thread_snapshot(tid) {
                fields.insert("thread_handle".to_string(), json!(thread.handle));
                fields.insert("state".to_string(), json!(thread.state));
                fields.insert("start_address".to_string(), json!(thread.start_address));
                fields.insert("wake_tick".to_string(), json!(thread.wake_tick));
            }
        }
        fields.insert(
            "ready_tids".to_string(),
            json!(self.core.scheduler.ready_thread_ids()),
        );
        self.log_runtime_event("THREAD_YIELD", fields)
    }

    pub fn log_native_yield_event(&mut self, mode: &str, blocking: bool) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("mode".to_string(), json!(mode));
        fields.insert("blocking".to_string(), json!(blocking));
        if let Some(tid) = self.core.scheduler.current_tid() {
            fields.insert("thread_tid".to_string(), json!(tid));
            if let Some(thread) = self.core.scheduler.thread_snapshot(tid) {
                fields.insert("state".to_string(), json!(thread.state));
                fields.insert("start_address".to_string(), json!(thread.start_address));
                fields.insert("wake_tick".to_string(), json!(thread.wake_tick));
            }
        }
        fields.insert(
            "ready_tids".to_string(),
            json!(self.core.scheduler.ready_thread_ids()),
        );
        self.log_runtime_event("NATIVE_YIELD", fields)
    }

    pub fn log_unicorn_api_yield_event(
        &mut self,
        address: u64,
        function: &str,
        yield_requested: bool,
        blocking: bool,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("address".to_string(), json!(address));
        fields.insert("function".to_string(), json!(function));
        fields.insert("yield_requested".to_string(), json!(yield_requested));
        fields.insert("blocking".to_string(), json!(blocking));
        if let Some(tid) = self.core.scheduler.current_tid() {
            fields.insert("thread_tid".to_string(), json!(tid));
            if let Some(thread) = self.core.scheduler.thread_snapshot(tid) {
                fields.insert("state".to_string(), json!(thread.state));
                fields.insert("start_address".to_string(), json!(thread.start_address));
                fields.insert("wake_tick".to_string(), json!(thread.wake_tick));
            }
        }
        fields.insert(
            "ready_tids".to_string(),
            json!(self.core.scheduler.ready_thread_ids()),
        );
        self.log_runtime_event("UNICORN_API_YIELD", fields)
    }

    pub fn log_heap_event(
        &mut self,
        marker: &str,
        heap: u32,
        address: u64,
        size: u64,
        source: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("heap".to_string(), json!(heap));
        fields.insert("address".to_string(), json!(address));
        fields.insert("size".to_string(), json!(size));
        fields.insert("source".to_string(), json!(source));
        self.log_runtime_event(marker, fields)
    }

    pub fn log_file_event(
        &mut self,
        marker: &str,
        handle: u32,
        path: &str,
        bytes: Option<u64>,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(handle));
        fields.insert("path".to_string(), json!(path));
        if let Some(bytes) = bytes {
            fields.insert("bytes".to_string(), json!(bytes));
        }
        self.log_runtime_event(marker, fields)
    }

    pub fn log_file_write_event(
        &mut self,
        handle: u32,
        path: &str,
        bytes: &[u8],
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(handle));
        fields.insert("path".to_string(), json!(path));
        fields.insert("bytes".to_string(), json!(bytes.len()));
        Self::add_payload_preview_field(&mut fields, bytes);
        self.log_runtime_event("FILE_WRITE", fields)
    }

    pub fn log_http_connect_event(
        &mut self,
        source: &str,
        connection_handle: u32,
    ) -> Result<(), VmError> {
        let Some(connection) = self.network_state.network.get_connection(connection_handle) else {
            return Ok(());
        };
        let mut fields = Map::new();
        fields.insert("source".to_string(), json!(source));
        fields.insert("connection_handle".to_string(), json!(connection_handle));
        fields.insert(
            "session_handle".to_string(),
            json!(connection.session_handle),
        );
        fields.insert("host".to_string(), json!(connection.server));
        fields.insert("port".to_string(), json!(connection.port));
        fields.insert("service".to_string(), json!(connection.service));
        if !connection.username.is_empty() {
            fields.insert("username".to_string(), json!(connection.username));
        }
        self.log_runtime_event("HTTP_CONNECT", fields)
    }

    pub fn log_http_request_event(
        &mut self,
        source: &str,
        request_handle: u32,
    ) -> Result<(), VmError> {
        let Some(request) = self.network_state.network.get_request(request_handle) else {
            return Ok(());
        };
        let route = self.network_state.network.request_route(request_handle);
        let mut fields = Map::new();
        fields.insert("source".to_string(), json!(source));
        fields.insert("request_handle".to_string(), json!(request_handle));
        fields.insert("parent_handle".to_string(), json!(request.parent_handle));
        fields.insert("verb".to_string(), json!(request.verb));
        fields.insert("target".to_string(), json!(request.target));
        fields.insert("version".to_string(), json!(request.version));
        fields.insert("sent".to_string(), json!(request.sent));
        if !request.referrer.is_empty() {
            fields.insert("referrer".to_string(), json!(request.referrer));
        }
        if !request.headers.is_empty() {
            fields.insert("headers".to_string(), json!(request.headers));
        }
        if let Some((host, target, verb)) = route {
            if !host.is_empty() {
                fields.insert("host".to_string(), json!(host));
            }
            if target != request.target {
                fields.insert("normalized_target".to_string(), json!(target));
            }
            if verb != request.verb {
                fields.insert("normalized_verb".to_string(), json!(verb));
            }
        }
        if let Some(connection) = self
            .network_state
            .network
            .get_connection(request.parent_handle)
        {
            fields.insert("port".to_string(), json!(connection.port));
            fields.insert("service".to_string(), json!(connection.service));
        }
        if !request.request_body.is_empty() {
            fields.insert("body_len".to_string(), json!(request.request_body.len()));
            Self::add_payload_preview_field(&mut fields, &request.request_body);
        }
        self.log_runtime_event("HTTP_REQUEST", fields)
    }

    pub fn log_artifact_hide(
        &mut self,
        artifact_type: &str,
        operation: &str,
        requested: &str,
        rule: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("artifact_type".to_string(), json!(artifact_type));
        fields.insert("operation".to_string(), json!(operation));
        fields.insert("requested".to_string(), json!(requested));
        fields.insert("rule".to_string(), json!(rule));
        self.log_runtime_event("ARTIFACT_HIDE", fields)
    }

    pub fn log_interception(
        &mut self,
        artifact_type: &str,
        operation: &str,
        requested: &str,
        action: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("artifact_type".to_string(), json!(artifact_type));
        fields.insert("operation".to_string(), json!(operation));
        fields.insert("requested".to_string(), json!(requested));
        fields.insert("action".to_string(), json!(action));
        self.log_runtime_event("INTERCEPTION", fields)
    }

    pub fn log_unsupported_import(
        &mut self,
        importing_module: &ModuleRecord,
        target_module: &str,
        target_function: &str,
        thunk: u64,
        reason: &str,
        resolved_module: Option<&str>,
        resolved_function: Option<&str>,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert(
            "importing_module".to_string(),
            json!(importing_module.name.clone()),
        );
        if let Some(path) = importing_module.path.as_ref() {
            fields.insert(
                "importing_path".to_string(),
                json!(path.to_string_lossy().to_string()),
            );
        }
        fields.insert("target_module".to_string(), json!(target_module));
        fields.insert("target_function".to_string(), json!(target_function));
        fields.insert("thunk".to_string(), json!(thunk));
        fields.insert("reason".to_string(), json!(reason));
        if let Some(module) = resolved_module {
            fields.insert("resolved_module".to_string(), json!(module));
        }
        if let Some(function) = resolved_function {
            fields.insert("resolved_function".to_string(), json!(function));
        }
        self.log_runtime_event_immediate("UNSUPPORTED_IMPORT", fields)
    }

    pub fn log_real_export_call(
        &mut self,
        address: u64,
        return_to: u64,
        target_module: &str,
        target_function: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("pc".to_string(), json!(address));
        fields.insert("return_to".to_string(), json!(return_to));
        fields.insert("target_module".to_string(), json!(target_module));
        fields.insert("target_function".to_string(), json!(target_function));
        if let Some(module) = self.core.modules.get_by_address(address) {
            let target_base = if module.visible_base != 0
                && address >= module.visible_base
                && address < module.visible_base.saturating_add(module.size)
            {
                module.visible_base
            } else {
                module.base
            };
            fields.insert("target_base".to_string(), json!(target_base));
        }
        self.add_address_ref_fields(&mut fields, "caller", return_to);
        self.log_runtime_event_immediate("REAL_EXPORT_CALL", fields)
    }

    pub fn log_unsupported_bound_stub(
        &mut self,
        address: u64,
        target_module: &str,
        target_function: &str,
        reason: &str,
    ) -> Result<(), VmError> {
        if self.core.config.exit_on_unsupported_hook {
            self.core.stop_reason = Some(RunStopReason::UnsupportedHook);
        }
        let mut fields = Map::new();
        fields.insert("pc".to_string(), json!(address));
        fields.insert("target_module".to_string(), json!(target_module));
        fields.insert("target_function".to_string(), json!(target_function));
        fields.insert("reason".to_string(), json!(reason));
        self.log_runtime_event_immediate("UNSUPPORTED_HOOK", fields)
    }

    pub fn log_unsupported_runtime_stub(
        &mut self,
        signature: &HookSignature,
        pc: u64,
        reason: &str,
    ) -> Result<(), VmError> {
        if self.core.config.exit_on_unsupported_hook {
            self.core.stop_reason = Some(RunStopReason::UnsupportedHook);
        }
        let mut fields = Map::new();
        fields.insert("pc".to_string(), json!(pc));
        fields.insert("target_module".to_string(), json!(signature.module));
        fields.insert("target_function".to_string(), json!(signature.function));
        fields.insert("reason".to_string(), json!(reason));
        self.log_runtime_event_immediate("UNSUPPORTED_RUNTIME", fields)
    }

    // ── Behavior collector helpers ──

    /// Record a network event into the in-memory behavior collector.
    pub(in crate::runtime::engine) fn record_network_event(
        &mut self,
        kind: &str,
        remote_host: Option<String>,
        remote_port: Option<u16>,
        data_size: Option<u64>,
        url: Option<String>,
        verb: Option<String>,
    ) {
        if !self.behavior.enabled {
            return;
        }
        self.behavior
            .network_events
            .push(crate::sandbox_result::NetworkEvent {
                tick_ms: self.dispatch.time.current().tick_ms,
                kind: kind.to_string(),
                protocol: None,
                remote_host,
                remote_port,
                data_size,
                url,
                verb,
            });
    }

    /// Record a file operation into the in-memory behavior collector.
    pub(in crate::runtime::engine) fn record_file_operation(
        &mut self,
        kind: &str,
        path: &str,
        result: Option<&str>,
    ) {
        if !self.behavior.enabled {
            return;
        }
        self.behavior
            .file_operations
            .push(crate::sandbox_result::FileOperation {
                tick_ms: self.dispatch.time.current().tick_ms,
                kind: kind.to_string(),
                path: path.to_string(),
                result: result.map(|s| s.to_string()),
            });
    }

    /// Record a registry operation into the in-memory behavior collector.
    pub(in crate::runtime::engine) fn record_registry_operation(
        &mut self,
        kind: &str,
        path: &str,
        value_name: Option<&str>,
        result: Option<&str>,
    ) {
        if !self.behavior.enabled {
            return;
        }
        self.behavior
            .registry_operations
            .push(crate::sandbox_result::RegistryOp {
                tick_ms: self.dispatch.time.current().tick_ms,
                kind: kind.to_string(),
                path: path.to_string(),
                value_name: value_name.map(|s| s.to_string()),
                result: result.map(|s| s.to_string()),
            });
    }

    /// Record a process operation into the in-memory behavior collector.
    pub(in crate::runtime::engine) fn record_process_operation(
        &mut self,
        kind: &str,
        image: Option<&str>,
        command_line: Option<&str>,
        pid: Option<u32>,
    ) {
        if !self.behavior.enabled {
            return;
        }
        self.behavior
            .process_operations
            .push(crate::sandbox_result::ProcessOp {
                tick_ms: self.dispatch.time.current().tick_ms,
                kind: kind.to_string(),
                image: image.map(|s| s.to_string()),
                command_line: command_line.map(|s| s.to_string()),
                pid,
            });
    }

    /// Record console output text into the in-memory behavior collector.
    #[allow(dead_code)]
    pub(in crate::runtime::engine) fn record_console_output(&mut self, text: &str) {
        if !self.behavior.enabled {
            return;
        }
        self.behavior.console_output.push_str(text);
    }
}
