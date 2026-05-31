use super::*;

impl VirtualExecutionEngine {
    pub fn log_process_exit(&mut self, reason: &str) -> Result<(), VmError> {
        // Flush any pending API suppression summary before process exit
        const SUPPRESS_THRESHOLD: u64 = 100;
        if self.dispatch.suppress_api_count > SUPPRESS_THRESHOLD {
            self.flush_api_suppression_summary()?;
        }
        if !self.core.api_logger.writes_marker("PROCESS_EXIT") {
            return Ok(());
        }
        let thread_counts = self.thread_state_counts();
        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(0u64));
        fields.insert("exit_code".to_string(), json!(self.core.exit_code));
        fields.insert("reason".to_string(), json!(reason));
        fields.insert("source".to_string(), json!("main"));
        if let Some(main_tid) = self.core.main_thread_tid {
            fields.insert("main_tid".to_string(), json!(main_tid));
            if let Some(state) = self.core.scheduler.thread_state(main_tid) {
                fields.insert("main_thread_state".to_string(), json!(state));
            }
        }
        fields.insert(
            "live_threads".to_string(),
            json!(thread_counts
                .iter()
                .filter(|(state, _)| state.as_str() != "terminated")
                .map(|(_, count)| *count)
                .sum::<u64>()),
        );
        fields.insert(
            "thread_states".to_string(),
            Self::thread_state_counts_value(&thread_counts),
        );
        self.core.api_logger.log_event(
            "PROCESS_EXIT",
            self.current_process_id(),
            self.current_log_tid(),
            self.dispatch.time.current().tick_ms,
            self.core.instruction_count,
            fields,
        )
    }

    pub fn log_run_stop(&mut self, reason: RunStopReason) -> Result<(), VmError> {
        // Flush any pending API suppression summary before run stop
        const SUPPRESS_THRESHOLD: u64 = 100;
        if self.dispatch.suppress_api_count > SUPPRESS_THRESHOLD {
            self.flush_api_suppression_summary()?;
        }
        if !self.core.api_logger.writes_marker("RUN_STOP") {
            return Ok(());
        }
        let thread_counts = self.thread_state_counts();
        let mut fields = Map::new();
        fields.insert("reason".to_string(), json!(reason.as_str()));
        fields.insert(
            "instruction_budget".to_string(),
            json!(self.core.config.max_instructions.max(1)),
        );
        fields.insert("exit_code".to_string(), json!(self.core.exit_code));
        if let Some(main_tid) = self.core.main_thread_tid {
            fields.insert("main_tid".to_string(), json!(main_tid));
            if let Some(state) = self.core.scheduler.thread_state(main_tid) {
                fields.insert("main_thread_state".to_string(), json!(state));
            }
        }
        fields.insert(
            "live_threads".to_string(),
            json!(thread_counts
                .iter()
                .filter(|(state, _)| state.as_str() != "terminated")
                .map(|(_, count)| *count)
                .sum::<u64>()),
        );
        fields.insert(
            "thread_states".to_string(),
            Self::thread_state_counts_value(&thread_counts),
        );
        self.log_runtime_event("RUN_STOP", fields)
    }

    /// Writes a final human-readable summary line explaining why the run
    /// ended, how many instructions were consumed vs. the budget, and the
    /// exit code (if any).
    pub fn log_final_summary(&mut self, stop_reason: RunStopReason) -> Result<(), VmError> {
        let marker = "RUN_FINAL";
        if !self.core.api_logger.writes_marker(marker) {
            return Ok(());
        }
        let total_instructions = self.core.instruction_count + self.core.emu_floor_instructions;
        let budget = self.core.config.max_instructions.max(1);
        let budget_pct = if budget > 0 {
            (total_instructions as f64 / budget as f64 * 100.0).min(999.9)
        } else {
            0.0
        };

        let reason_text = match stop_reason {
            RunStopReason::InstructionBudgetExhausted => {
                format!(
                    "指令预算耗尽 ({} / {} = {:.1}%)",
                    total_instructions, budget, budget_pct
                )
            }
            RunStopReason::ProcessExit => {
                format!(
                    "程序主动退出, exit_code={} ({} / {} 指令, {:.1}%)",
                    match self.core.exit_code {
                        Some(c) => format!("{c}"),
                        None => "?".to_string(),
                    },
                    total_instructions,
                    budget,
                    budget_pct,
                )
            }
            RunStopReason::MainThreadTerminated => {
                format!(
                    "主线程终止, exit_code={} ({} / {} 指令, {:.1}%)",
                    match self.core.exit_code {
                        Some(c) => format!("{c}"),
                        None => "?".to_string(),
                    },
                    total_instructions,
                    budget,
                    budget_pct,
                )
            }
            RunStopReason::AllThreadsTerminated => {
                format!(
                    "全部线程终止, exit_code={} ({} / {} 指令, {:.1}%)",
                    match self.core.exit_code {
                        Some(c) => format!("{c}"),
                        None => "?".to_string(),
                    },
                    total_instructions,
                    budget,
                    budget_pct,
                )
            }
            RunStopReason::SchedulerIdle => {
                format!(
                    "调度器空闲 (无就绪线程), {} / {} 指令 ({:.1}%)",
                    total_instructions, budget, budget_pct
                )
            }
            RunStopReason::UnsupportedHook => {
                format!(
                    "不支持的 Hook 导致退出, {} / {} 指令 ({:.1}%)",
                    total_instructions, budget, budget_pct
                )
            }
            RunStopReason::MemoryAccessViolation => {
                format!(
                    "内存访问越界, {} / {} 指令 ({:.1}%)",
                    total_instructions, budget, budget_pct
                )
            }
            RunStopReason::RunComplete => {
                format!(
                    "运行完成, {} / {} 指令 ({:.1}%)",
                    total_instructions, budget, budget_pct
                )
            }
        };

        let mut fields = Map::new();
        fields.insert("reason".to_string(), json!(stop_reason.as_str()));
        fields.insert("total_instructions".to_string(), json!(total_instructions));
        fields.insert("instruction_budget".to_string(), json!(budget));
        fields.insert("exit_code".to_string(), json!(self.core.exit_code));
        fields.insert("summary".to_string(), json!(reason_text));

        self.log_runtime_event_immediate(marker, fields)
    }

    /// Writes a final summary on error paths (crash, emulation failure, etc.).
    pub fn log_error_summary(&mut self, error: &str) -> Result<(), VmError> {
        let marker = "RUN_FINAL";
        if !self.core.api_logger.writes_marker(marker) {
            return Ok(());
        }
        let total_instructions = self.core.instruction_count + self.core.emu_floor_instructions;
        let budget = self.core.config.max_instructions.max(1);
        let budget_pct = if budget > 0 {
            (total_instructions as f64 / budget as f64 * 100.0).min(999.9)
        } else {
            0.0
        };
        let reason_text = format!(
            "运行异常: {} ({} / {} 指令, {:.1}%)",
            error, total_instructions, budget, budget_pct
        );

        let mut fields = Map::new();
        fields.insert("reason".to_string(), json!("error"));
        fields.insert("error".to_string(), json!(error));
        fields.insert("total_instructions".to_string(), json!(total_instructions));
        fields.insert("instruction_budget".to_string(), json!(budget));
        fields.insert("exit_code".to_string(), json!(self.core.exit_code));
        fields.insert("summary".to_string(), json!(reason_text));

        self.log_runtime_event_immediate(marker, fields)
    }

    pub fn log_api_hotspot_summary(&mut self) -> Result<(), VmError> {
        if !self.core.api_logger.writes_marker("API_HOTSPOT")
            || self.core.api_call_counts.is_empty()
        {
            return Ok(());
        }
        let total_calls = self
            .core
            .api_call_counts
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        let mut hottest = self
            .core
            .api_call_counts
            .iter()
            .map(|(target, count)| (target.clone(), *count))
            .collect::<Vec<_>>();
        hottest.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        let top_calls = hottest
            .into_iter()
            .take(10)
            .map(|(target, count)| json!({ "target": target, "count": count }))
            .collect::<Vec<_>>();
        let mut fields = Map::new();
        fields.insert("total_calls".to_string(), json!(total_calls));
        fields.insert(
            "unique_targets".to_string(),
            json!(self.core.api_call_counts.len() as u64),
        );
        fields.insert("top_calls".to_string(), json!(top_calls));
        self.log_runtime_event("API_HOTSPOT", fields)
    }

    pub fn log_user32_hotspot_summary(&mut self) -> Result<(), VmError> {
        if !self.core.api_logger.writes_marker("USER32_HOTSPOT") {
            return Ok(());
        }
        let state = &self.ui.user32_state;
        let mut fields = Map::new();
        fields.insert(
            "get_message_calls".to_string(),
            json!(state.get_message_calls),
        );
        fields.insert(
            "peek_message_calls".to_string(),
            json!(state.peek_message_calls),
        );
        fields.insert(
            "translate_message_calls".to_string(),
            json!(state.translate_message_calls),
        );
        fields.insert(
            "dispatch_message_calls".to_string(),
            json!(state.dispatch_message_calls),
        );
        fields.insert("set_timer_calls".to_string(), json!(state.set_timer_calls));
        fields.insert(
            "kill_timer_calls".to_string(),
            json!(state.kill_timer_calls),
        );
        fields.insert(
            "synthetic_timer_messages".to_string(),
            json!(state.synthetic_timer_messages),
        );
        fields.insert(
            "synthetic_idle_messages".to_string(),
            json!(state.synthetic_idle_messages),
        );
        fields.insert(
            "hook_callback_dispatches".to_string(),
            json!(state.hook_callback_dispatches),
        );
        fields.insert(
            "active_timers".to_string(),
            json!(self.user32_active_timer_count()),
        );
        fields.insert(
            "active_hooks".to_string(),
            json!(self.user32_active_hook_count()),
        );
        self.log_runtime_event("USER32_HOTSPOT", fields)
    }

    pub fn log_emu_stop(&mut self, phase: &str, pc: u64, error: &str) -> Result<(), VmError> {
        if !self.core.api_logger.writes_marker("EMU_STOP") {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("phase".to_string(), json!(phase));
        fields.insert("error".to_string(), json!(error));
        fields.insert("pc".to_string(), json!(pc));
        self.core.api_logger.log_event(
            "EMU_STOP",
            self.current_process_id(),
            self.current_log_tid(),
            self.dispatch.time.current().tick_ms,
            self.core.instruction_count,
            fields,
        )
    }

    pub fn log_runtime_event_immediate(
        &mut self,
        marker: &str,
        fields: Map<String, serde_json::Value>,
    ) -> Result<(), VmError> {
        if !self.core.api_logger.writes_marker(marker) {
            return Ok(());
        }
        self.core.api_logger.log_event(
            marker,
            self.current_process_id(),
            self.current_log_tid(),
            self.dispatch.time.current().tick_ms,
            self.core.instruction_count,
            fields,
        )?;
        self.core.api_logger.flush()
    }

    pub fn log_runtime_event(
        &mut self,
        marker: &str,
        fields: Map<String, serde_json::Value>,
    ) -> Result<(), VmError> {
        if !self.core.api_logger.writes_marker(marker) {
            return Ok(());
        }
        self.core.api_logger.log_event(
            marker,
            self.current_process_id(),
            self.current_log_tid(),
            self.dispatch.time.current().tick_ms,
            self.core.instruction_count,
            fields,
        )
    }

    pub fn thread_state_counts(&self) -> BTreeMap<String, u64> {
        let mut counts = BTreeMap::<String, u64>::new();
        for thread in self.core.scheduler.thread_snapshots() {
            *counts.entry(thread.state.to_string()).or_insert(0) += 1;
        }
        counts
    }

    pub fn dll_reason_name(reason: u64) -> &'static str {
        match reason {
            DLL_PROCESS_ATTACH => "process_attach",
            DLL_PROCESS_DETACH => "process_detach",
            DLL_THREAD_ATTACH => "thread_attach",
            DLL_THREAD_DETACH => "thread_detach",
            _ => "unknown",
        }
    }

    pub fn thread_state_counts_value(counts: &BTreeMap<String, u64>) -> serde_json::Value {
        let mut fields = Map::new();
        for (state, count) in counts {
            fields.insert(state.clone(), json!(count));
        }
        serde_json::Value::Object(fields)
    }

    pub fn resolve_run_stop_reason(&mut self) -> RunStopReason {
        if let Some(reason) = self.core.stop_reason {
            return reason;
        }
        let reason = if self.core.process_exit_requested {
            RunStopReason::ProcessExit
        } else if !self.core.scheduler.has_live_threads() {
            RunStopReason::AllThreadsTerminated
        } else if self
            .core
            .main_thread_tid
            .and_then(|tid| self.core.scheduler.thread_state(tid))
            == Some("terminated")
        {
            RunStopReason::MainThreadTerminated
        } else if self.core.instruction_count >= self.core.config.max_instructions.max(1) {
            RunStopReason::InstructionBudgetExhausted
        } else if self.core.loaded {
            RunStopReason::SchedulerIdle
        } else {
            RunStopReason::RunComplete
        };
        self.core.stop_reason = Some(reason);
        reason
    }

    pub fn add_address_ref_fields(
        &self,
        fields: &mut Map<String, serde_json::Value>,
        prefix: &str,
        address: u64,
    ) {
        let reference = self.address_ref(address);
        fields.insert(format!("{prefix}_owner"), json!(reference.owner));
        if let Some(module) = reference.module {
            fields.insert(format!("{prefix}_module"), json!(module));
        }
        if let Some(module_base) = reference.module_base {
            fields.insert(format!("{prefix}_module_base"), json!(module_base));
        }
        if let Some(rva) = reference.rva {
            fields.insert(format!("{prefix}_rva"), json!(rva));
        }
        if let Some(module_path) = reference.module_path {
            fields.insert(format!("{prefix}_module_path"), json!(module_path));
        }
        if let Some(region) = reference.region {
            fields.insert(format!("{prefix}_region"), json!(region));
        }
        if let Some(region_base) = reference.region_base {
            fields.insert(format!("{prefix}_region_base"), json!(region_base));
        }
        if let Some(region_offset) = reference.region_offset {
            fields.insert(format!("{prefix}_region_offset"), json!(region_offset));
        }
    }

    pub fn register_map_value(registers: &RegisterFile) -> serde_json::Value {
        let map = register_file_to_map(registers);
        let mut values = Map::new();
        for (name, value) in &map {
            values.insert(name.clone(), json!(value));
        }
        serde_json::Value::Object(values)
    }

    pub fn register_ref_map_value(&self, registers: &RegisterFile) -> serde_json::Value {
        let map = register_file_to_map(registers);
        let mut values = Map::new();
        for (name, value) in &map {
            if *value == 0 {
                continue;
            }
            let reference = self.address_ref(*value);
            if reference.owner == "unknown" {
                continue;
            }
            values.insert(name.clone(), reference.to_json_value());
        }
        serde_json::Value::Object(values)
    }

    pub fn word_map_value(words: &BTreeMap<String, u64>) -> serde_json::Value {
        let mut values = Map::new();
        for (name, value) in words {
            values.insert(name.clone(), json!(value));
        }
        serde_json::Value::Object(values)
    }
}

impl VirtualExecutionEngine {
    pub fn format_native_delta(before: u64, after: u64) -> String {
        if after >= before {
            format!("+0x{:X}", after - before)
        } else {
            format!("-0x{:X}", before - after)
        }
    }

    pub fn native_loop_delta_entry_value(&self, delta: &LoopValueDelta) -> serde_json::Value {
        let mut entry = Map::new();
        entry.insert("before".to_string(), json!(delta.before));
        entry.insert("after".to_string(), json!(delta.after));
        entry.insert(
            "delta".to_string(),
            json!(Self::format_native_delta(delta.before, delta.after)),
        );
        let before_ref = self.address_ref(delta.before);
        if before_ref.owner != "unknown" && before_ref.owner != "NULL" {
            entry.insert("before_ref".to_string(), before_ref.to_json_value());
        }
        let after_ref = self.address_ref(delta.after);
        if after_ref.owner != "unknown" && after_ref.owner != "NULL" {
            entry.insert("after_ref".to_string(), after_ref.to_json_value());
        }
        serde_json::Value::Object(entry)
    }

    pub fn native_loop_delta_entries_value(
        &self,
        deltas: &BTreeMap<String, LoopValueDelta>,
    ) -> serde_json::Value {
        let mut values = Map::new();
        for (name, delta) in deltas {
            values.insert(name.clone(), self.native_loop_delta_entry_value(delta));
        }
        serde_json::Value::Object(values)
    }

    pub fn native_loop_state_delta_value(&self, delta: &LoopStateDelta) -> serde_json::Value {
        let mut record = Map::new();
        record.insert(
            "registers".to_string(),
            self.native_loop_delta_entries_value(&delta.registers),
        );
        record.insert(
            "stack_words".to_string(),
            self.native_loop_delta_entries_value(&delta.stack_words),
        );
        serde_json::Value::Object(record)
    }

    pub fn native_loop_phase_deltas_value(
        &self,
        phase_deltas: &[LoopPhaseDelta],
    ) -> serde_json::Value {
        serde_json::Value::Array(
            phase_deltas
                .iter()
                .map(|phase_delta| {
                    let mut record = Map::new();
                    record.insert("phase".to_string(), json!(phase_delta.phase));
                    record.insert("pc".to_string(), json!(phase_delta.pc));
                    record.insert("size".to_string(), json!(phase_delta.size));
                    record.insert(
                        "changed_values".to_string(),
                        json!(phase_delta.change_count()),
                    );
                    record.insert(
                        "pc_ref".to_string(),
                        self.address_ref(phase_delta.pc).to_json_value(),
                    );
                    record.insert(
                        "state_delta".to_string(),
                        self.native_loop_state_delta_value(&phase_delta.state_delta),
                    );
                    serde_json::Value::Object(record)
                })
                .collect(),
        )
    }

    pub fn native_loop_phase_sequence_value(
        &self,
        phase_summaries: &[LoopPhaseSummary],
    ) -> serde_json::Value {
        serde_json::Value::Array(
            phase_summaries
                .iter()
                .map(|phase_summary| {
                    let mut record = Map::new();
                    record.insert("phase".to_string(), json!(phase_summary.phase));
                    record.insert("pc".to_string(), json!(phase_summary.pc));
                    record.insert("size".to_string(), json!(phase_summary.size));
                    record.insert(
                        "changed_values".to_string(),
                        json!(phase_summary.change_count()),
                    );
                    record.insert(
                        "changed_registers".to_string(),
                        serde_json::Value::Array(
                            phase_summary
                                .changed_registers
                                .iter()
                                .map(|name| json!(name))
                                .collect(),
                        ),
                    );
                    record.insert(
                        "changed_stack_words".to_string(),
                        serde_json::Value::Array(
                            phase_summary
                                .changed_stack_words
                                .iter()
                                .map(|name| json!(name))
                                .collect(),
                        ),
                    );
                    record.insert(
                        "pc_ref".to_string(),
                        self.address_ref(phase_summary.pc).to_json_value(),
                    );
                    serde_json::Value::Object(record)
                })
                .collect(),
        )
    }

    pub fn native_loop_register_hotspots_value(
        &self,
        phase_summaries: &[LoopPhaseSummary],
        state_delta: Option<&LoopStateDelta>,
    ) -> serde_json::Value {
        let mut hotspots = BTreeMap::<String, Vec<usize>>::new();
        for phase_summary in phase_summaries {
            for name in &phase_summary.changed_registers {
                hotspots
                    .entry(name.clone())
                    .or_default()
                    .push(phase_summary.phase);
            }
        }
        let mut entries = hotspots.into_iter().collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            right
                .1
                .len()
                .cmp(&left.1.len())
                .then_with(|| left.0.cmp(&right.0))
        });
        serde_json::Value::Array(
            entries
                .into_iter()
                .map(|(name, phases)| {
                    let mut record = Map::new();
                    record.insert("name".to_string(), json!(name));
                    record.insert("phase_hits".to_string(), json!(phases.len()));
                    record.insert(
                        "phases".to_string(),
                        serde_json::Value::Array(
                            phases.iter().copied().map(|phase| json!(phase)).collect(),
                        ),
                    );
                    if let Some(delta) = state_delta.and_then(|delta| delta.registers.get(&name)) {
                        record.insert(
                            "loop_start_delta".to_string(),
                            self.native_loop_delta_entry_value(delta),
                        );
                    }
                    serde_json::Value::Object(record)
                })
                .collect(),
        )
    }

    pub fn native_loop_stack_hotspots_value(
        &self,
        phase_summaries: &[LoopPhaseSummary],
        state_delta: Option<&LoopStateDelta>,
    ) -> serde_json::Value {
        let mut hotspots = BTreeMap::<String, Vec<usize>>::new();
        for phase_summary in phase_summaries {
            for name in &phase_summary.changed_stack_words {
                hotspots
                    .entry(name.clone())
                    .or_default()
                    .push(phase_summary.phase);
            }
        }
        let mut entries = hotspots.into_iter().collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            right
                .1
                .len()
                .cmp(&left.1.len())
                .then_with(|| left.0.cmp(&right.0))
        });
        serde_json::Value::Array(
            entries
                .into_iter()
                .map(|(name, phases)| {
                    let mut record = Map::new();
                    record.insert("name".to_string(), json!(name));
                    record.insert("phase_hits".to_string(), json!(phases.len()));
                    record.insert(
                        "phases".to_string(),
                        serde_json::Value::Array(
                            phases.iter().copied().map(|phase| json!(phase)).collect(),
                        ),
                    );
                    if let Some(delta) = state_delta.and_then(|delta| delta.stack_words.get(&name))
                    {
                        record.insert(
                            "loop_start_delta".to_string(),
                            self.native_loop_delta_entry_value(delta),
                        );
                    }
                    serde_json::Value::Object(record)
                })
                .collect(),
        )
    }

    pub fn native_loop_value(&self, snapshot: &NativeLoopSnapshot) -> serde_json::Value {
        let mut record = Map::new();
        record.insert("period".to_string(), json!(snapshot.period));
        record.insert("repeats".to_string(), json!(snapshot.repeats));
        record.insert(
            "covered_blocks".to_string(),
            json!(snapshot.repeats.saturating_mul(snapshot.period as u64)),
        );
        record.insert(
            "sequence".to_string(),
            serde_json::Value::Array(
                snapshot
                    .blocks
                    .iter()
                    .map(|(pc, size)| {
                        let mut block = Map::new();
                        block.insert("pc".to_string(), json!(pc));
                        block.insert("size".to_string(), json!(size));
                        block.insert("pc_ref".to_string(), self.address_ref(*pc).to_json_value());
                        serde_json::Value::Object(block)
                    })
                    .collect(),
            ),
        );
        if !snapshot.phase_summaries.is_empty() {
            record.insert(
                "phase_sequence".to_string(),
                self.native_loop_phase_sequence_value(&snapshot.phase_summaries),
            );
            record.insert(
                "register_hotspots".to_string(),
                self.native_loop_register_hotspots_value(
                    &snapshot.phase_summaries,
                    snapshot.state_delta.as_ref(),
                ),
            );
            record.insert(
                "stack_hotspots".to_string(),
                self.native_loop_stack_hotspots_value(
                    &snapshot.phase_summaries,
                    snapshot.state_delta.as_ref(),
                ),
            );
        }
        if let Some(state_delta) = snapshot.state_delta.as_ref() {
            record.insert(
                "state_delta".to_string(),
                self.native_loop_state_delta_value(state_delta),
            );
        }
        if !snapshot.phase_deltas.is_empty() {
            record.insert(
                "phase_deltas".to_string(),
                self.native_loop_phase_deltas_value(&snapshot.phase_deltas),
            );
        }
        serde_json::Value::Object(record)
    }
}

impl VirtualExecutionEngine {
    pub fn native_hot_blocks_value(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.trace
                .native_trace
                .top_blocks(NATIVE_PROGRESS_TOP_BLOCK_LIMIT)
                .into_iter()
                .map(|((pc, size), hits)| {
                    let mut block = Map::new();
                    block.insert("pc".to_string(), json!(pc));
                    block.insert("size".to_string(), json!(size));
                    block.insert("hits".to_string(), json!(hits));
                    let reference = self.address_ref(pc);
                    block.insert("pc_ref".to_string(), reference.to_json_value());
                    serde_json::Value::Object(block)
                })
                .collect(),
        )
    }

    pub fn log_instruction_budget_exhausted(
        &mut self,
        phase: &str,
        pc: u64,
    ) -> Result<(), VmError> {
        if !self.core.api_logger.enabled() {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("phase".to_string(), json!(phase));
        fields.insert(
            "instruction_budget".to_string(),
            json!(self.core.config.max_instructions.max(1)),
        );
        fields.insert("pc".to_string(), json!(pc));
        self.add_address_ref_fields(&mut fields, "pc", pc);
        self.log_runtime_event_immediate("INSTRUCTION_BUDGET", fields)
    }

    pub fn log_native_progress(&mut self, pc: u64, size: u32) -> Result<(), VmError> {
        if !self.core.api_logger.writes_marker("NATIVE_PROGRESS")
            || self.trace.native_trace.total_blocks() == 0
        {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("pc".to_string(), json!(pc));
        fields.insert("size".to_string(), json!(size));
        fields.insert(
            "blocks_seen".to_string(),
            json!(self.trace.native_trace.total_blocks()),
        );
        fields.insert(
            "unique_blocks".to_string(),
            json!(self.trace.native_trace.unique_blocks()),
        );
        fields.insert("hot_blocks".to_string(), self.native_hot_blocks_value());
        if let Some(active_loop) = self.trace.native_trace.active_loop() {
            fields.insert(
                "active_loop".to_string(),
                self.native_loop_value(&active_loop),
            );
        }
        self.add_address_ref_fields(&mut fields, "pc", pc);
        self.log_runtime_event("NATIVE_PROGRESS", fields)
    }

    pub fn log_native_summary(&mut self, reason: RunStopReason) -> Result<(), VmError> {
        if !self.core.api_logger.writes_marker("NATIVE_SUMMARY")
            || self.trace.native_trace.total_blocks() == 0
        {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("reason".to_string(), json!(reason.as_str()));
        fields.insert(
            "blocks_seen".to_string(),
            json!(self.trace.native_trace.total_blocks()),
        );
        fields.insert(
            "unique_blocks".to_string(),
            json!(self.trace.native_trace.unique_blocks()),
        );
        fields.insert("hot_blocks".to_string(), self.native_hot_blocks_value());
        if let Some(active_loop) = self.trace.native_trace.active_loop() {
            fields.insert(
                "active_loop".to_string(),
                self.native_loop_value(&active_loop),
            );
        }
        self.log_runtime_event("NATIVE_SUMMARY", fields)
    }

    pub fn log_native_loop(&mut self, snapshot: &NativeLoopSnapshot) -> Result<(), VmError> {
        if !self.core.api_logger.writes_marker("NATIVE_LOOP") {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("loop".to_string(), self.native_loop_value(snapshot));
        self.log_runtime_event("NATIVE_LOOP", fields)
    }

    pub fn log_native_block(
        &mut self,
        pc: u64,
        size: u32,
        snapshot: Option<&NativeBlockSnapshot>,
    ) -> Result<(), VmError> {
        if !self.core.api_logger.native_trace_sampling_enabled() {
            return Ok(());
        }
        let update =
            self.trace
                .native_trace
                .record_block(self.core.instruction_count, pc, size, snapshot);
        let mut fields = Map::new();
        fields.insert("pc".to_string(), json!(pc));
        fields.insert("size".to_string(), json!(size));
        self.add_address_ref_fields(&mut fields, "pc", pc);
        self.log_runtime_event("NATIVE_BLOCK", fields)?;
        if let Some(loop_snapshot) = update.loop_snapshot.as_ref() {
            self.log_native_loop(loop_snapshot)?;
        }
        if update.should_log_progress {
            self.log_native_progress(pc, size)?;
        }
        Ok(())
    }

    pub fn log_null_call_fault(
        &mut self,
        pc: u64,
        fault_addr: u64,
        regs: &RegisterFile,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("kind".to_string(), json!("null_call"));
        fields.insert("pc".to_string(), json!(pc));
        fields.insert("fault_addr".to_string(), json!(fault_addr));
        self.add_address_ref_fields(&mut fields, "pc", pc);
        if self.core.arch.is_x64() {
            fields.insert("rax".to_string(), json!(regs.rax));
            fields.insert("rcx".to_string(), json!(regs.rcx));
            fields.insert("rdx".to_string(), json!(regs.rdx));
            fields.insert("rsp".to_string(), json!(regs.rsp));
            fields.insert("r8".to_string(), json!(regs.r8));
            fields.insert("r9".to_string(), json!(regs.r9));
        } else {
            fields.insert("eax".to_string(), json!(regs.eax));
            fields.insert("ecx".to_string(), json!(regs.ecx));
            fields.insert("edx".to_string(), json!(regs.edx));
            fields.insert("esp".to_string(), json!(regs.esp));
        }
        self.core.api_logger.log_event(
            "NULL_CALL",
            self.current_process_id(),
            self.current_log_tid(),
            self.dispatch.time.current().tick_ms,
            self.core.instruction_count,
            fields,
        )
    }

    pub fn log_native_fault(
        &mut self,
        kind: &str,
        access: &str,
        pc: u64,
        address: u64,
        size: usize,
        registers: Option<&RegisterFile>,
        detail: Option<&str>,
    ) -> Result<(), VmError> {
        if !self.core.api_logger.writes_marker("NATIVE_FAULT") {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("kind".to_string(), json!(kind));
        fields.insert("access".to_string(), json!(access));
        fields.insert("pc".to_string(), json!(pc));
        fields.insert("address".to_string(), json!(address));
        fields.insert("size".to_string(), json!(size));
        self.add_address_ref_fields(&mut fields, "pc", pc);
        self.add_address_ref_fields(&mut fields, "address", address);
        if let Ok(bytes) = self.core.modules.memory().read(pc, 16) {
            fields.insert(
                "pc_bytes".to_string(),
                json!(Self::format_runtime_bytes(&bytes)),
            );
        }
        if let Some(registers) = registers {
            fields.insert("registers".to_string(), Self::register_map_value(registers));
            fields.insert(
                "register_refs".to_string(),
                self.register_ref_map_value(registers),
            );
        }
        if let Some(detail) = detail {
            fields.insert("detail".to_string(), json!(detail));
        }
        self.log_runtime_event_immediate("NATIVE_FAULT", fields)
    }

    pub fn log_native_fault_window(
        &mut self,
        snapshots: &VecDeque<NativeBlockSnapshot>,
    ) -> Result<(), VmError> {
        if !self.core.api_logger.writes_marker("NATIVE_TRACE_WINDOW") || snapshots.is_empty() {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("blocks".to_string(), json!(snapshots.len()));
        fields.insert(
            "window".to_string(),
            serde_json::Value::Array(
                snapshots
                    .iter()
                    .map(|snapshot| {
                        let mut block = Map::new();
                        block.insert("pc".to_string(), json!(snapshot.pc));
                        block.insert("size".to_string(), json!(snapshot.size));
                        block.insert(
                            "registers".to_string(),
                            Self::register_map_value(&snapshot.registers),
                        );
                        block.insert(
                            "register_refs".to_string(),
                            self.register_ref_map_value(&snapshot.registers),
                        );
                        block.insert(
                            "stack_words".to_string(),
                            Self::word_map_value(&snapshot.stack_words),
                        );
                        serde_json::Value::Object(block)
                    })
                    .collect(),
            ),
        );
        self.log_runtime_event_immediate("NATIVE_TRACE_WINDOW", fields)
    }

    pub fn log_native_code_write(
        &mut self,
        address: u64,
        size: usize,
        bytes: &[u8],
    ) -> Result<(), VmError> {
        if !self.core.api_logger.writes_marker("NATIVE_CODE_WRITE") {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("address".to_string(), json!(address));
        fields.insert("size".to_string(), json!(size));
        fields.insert(
            "bytes_preview".to_string(),
            json!(Self::format_runtime_bytes(bytes)),
        );
        self.add_address_ref_fields(&mut fields, "address", address);
        self.log_runtime_event("NATIVE_CODE_WRITE", fields)
    }
}
