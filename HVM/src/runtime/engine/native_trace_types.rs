//! Native trace types: loop detection, block snapshots, Unicorn fault types.
//!
//! Extracted from engine.rs for maintainability.

use std::collections::{BTreeMap, VecDeque};

use super::constants::*;
use super::VirtualExecutionEngine;
use crate::error::VmError;
use crate::runtime::thread_context::RegisterFile;
use crate::runtime::unicorn::{UcEngine, UnicornApi};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnicornFaultAccess {
    Read,
    Write,
    Execute,
}

impl UnicornFaultAccess {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnicornFault {
    pub(super) access: UnicornFaultAccess,
    pub(super) address: u64,
    pub(super) size: usize,
    pub(super) pc: u64,
    pub(super) exception_code: Option<u32>,
    pub(super) exception_information_count: u32,
    pub(super) exception_information: [u64; 2],
}

impl UnicornFault {
    pub(super) fn memory_access(
        access: UnicornFaultAccess,
        address: u64,
        size: usize,
        pc: u64,
    ) -> Self {
        Self {
            access,
            address,
            size,
            pc,
            exception_code: None,
            exception_information_count: 0,
            exception_information: [0, 0],
        }
    }

    pub(super) fn cpu_exception(code: u32, pc: u64) -> Self {
        Self {
            access: UnicornFaultAccess::Execute,
            address: pc,
            size: 1,
            pc,
            exception_code: Some(code),
            exception_information_count: 0,
            exception_information: [0, 0],
        }
    }
}

#[allow(dead_code)]
pub(super) struct UnicornRunContext {
    pub(super) engine: *mut VirtualExecutionEngine,
    pub(super) api: *const UnicornApi,
    pub(super) uc: *mut UcEngine,
    pub(super) callback_error: Option<VmError>,
    pub(super) pending_fault: Option<UnicornFault>,
    pub(super) pending_protected_fetch: Option<PendingProtectedFetchAction>,
    pub(super) pending_writes: Vec<(u64, usize)>,
    pub(super) pending_write_bytes: u64,
    pub(super) suppress_mem_write_hook: bool,
    pub(super) last_native_block: Option<(u64, u32)>,
    pub(super) recent_blocks: VecDeque<NativeBlockSnapshot>,
    pub(super) logged_ldr_module_snapshot: bool,
    pub(super) recent_sensitive_reads: VecDeque<u64>,
    pub(super) recent_branch_trace: VecDeque<u64>,
    pub(super) branch_trace_until_instruction: u64,
    pub(super) last_sensitive_chain_key: Option<u64>,
}

#[derive(Debug, Clone)]
pub(super) enum PendingProtectedFetchAction {
    DispatchBound {
        address: u64,
    },
    SimulateReturn {
        address: u64,
        binding: Option<(String, String)>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeCallRunMode {
    Standalone,
    EntryFrame,
}

#[derive(Debug, Clone)]
pub struct NativeBlockSnapshot {
    pub(super) pc: u64,
    pub(super) size: u32,
    pub(super) registers: RegisterFile,
    pub(super) stack_words: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopValueDelta {
    pub(super) before: u64,
    pub(super) after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoopStateDelta {
    pub(super) registers: BTreeMap<String, LoopValueDelta>,
    pub(super) stack_words: BTreeMap<String, LoopValueDelta>,
}

impl LoopStateDelta {
    pub(super) fn is_empty(&self) -> bool {
        self.registers.is_empty() && self.stack_words.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopPhaseDelta {
    pub(super) phase: usize,
    pub(super) pc: u64,
    pub(super) size: u32,
    pub(super) state_delta: LoopStateDelta,
}

impl LoopPhaseDelta {
    pub(super) fn change_count(&self) -> usize {
        self.state_delta.registers.len() + self.state_delta.stack_words.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopPhaseSummary {
    pub(super) phase: usize,
    pub(super) pc: u64,
    pub(super) size: u32,
    pub(super) changed_registers: Vec<String>,
    pub(super) changed_stack_words: Vec<String>,
}

impl LoopPhaseSummary {
    pub(super) fn change_count(&self) -> usize {
        self.changed_registers.len() + self.changed_stack_words.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLoopSnapshot {
    pub(super) blocks: Vec<(u64, u32)>,
    pub(super) observed_blocks: Vec<(u64, u32)>,
    pub(super) period: usize,
    pub(super) repeats: u64,
    pub(super) state_delta: Option<LoopStateDelta>,
    pub(super) phase_summaries: Vec<LoopPhaseSummary>,
    pub(super) phase_deltas: Vec<LoopPhaseDelta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ActiveNativeLoop {
    pub(super) blocks: Vec<(u64, u32)>,
    pub(super) observed_blocks: Vec<(u64, u32)>,
    pub(super) period: usize,
    pub(super) repeats: u64,
    pub(super) state_delta: Option<LoopStateDelta>,
    pub(super) phase_summaries: Vec<LoopPhaseSummary>,
    pub(super) phase_deltas: Vec<LoopPhaseDelta>,
    pub(super) next_emit_repeats: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NativeTraceUpdate {
    pub(super) should_log_progress: bool,
    pub(super) loop_snapshot: Option<NativeLoopSnapshot>,
}

#[derive(Debug)]
pub struct NativeTraceState {
    pub(super) total_blocks: u64,
    pub(super) block_hits: BTreeMap<(u64, u32), u64>,
    pub(super) recent_sequence: VecDeque<(u64, u32)>,
    pub(super) recent_snapshots: VecDeque<NativeBlockSnapshot>,
    pub(super) active_loop: Option<ActiveNativeLoop>,
    pub(super) next_progress_instruction: u64,
}

impl NativeTraceState {
    pub(super) fn reset(&mut self) {
        self.total_blocks = 0;
        self.block_hits.clear();
        self.recent_sequence.clear();
        self.recent_snapshots.clear();
        self.active_loop = None;
        self.next_progress_instruction = NATIVE_PROGRESS_INTERVAL_INSTRUCTIONS;
    }

    pub(super) fn record_block(
        &mut self,
        instruction_count: u64,
        pc: u64,
        size: u32,
        snapshot: Option<&NativeBlockSnapshot>,
    ) -> NativeTraceUpdate {
        self.total_blocks = self.total_blocks.saturating_add(1);
        *self.block_hits.entry((pc, size)).or_insert(0) += 1;
        self.recent_sequence.push_back((pc, size));
        if self.recent_sequence.len() > NATIVE_LOOP_HISTORY_BLOCKS {
            self.recent_sequence.pop_front();
        }
        if let Some(snapshot) = snapshot {
            self.recent_snapshots.push_back(snapshot.clone());
            if self.recent_snapshots.len() > NATIVE_LOOP_HISTORY_BLOCKS {
                self.recent_snapshots.pop_front();
            }
        }
        let loop_snapshot = self.update_loop_detection();
        let should_log_progress = if instruction_count < self.next_progress_instruction {
            false
        } else {
            self.next_progress_instruction =
                instruction_count.saturating_add(NATIVE_PROGRESS_INTERVAL_INSTRUCTIONS);
            true
        };
        NativeTraceUpdate {
            should_log_progress,
            loop_snapshot,
        }
    }

    pub(super) fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    pub(super) fn unique_blocks(&self) -> usize {
        self.block_hits.len()
    }

    pub(super) fn active_loop(&self) -> Option<NativeLoopSnapshot> {
        self.active_loop.as_ref().map(|active| NativeLoopSnapshot {
            blocks: active.blocks.clone(),
            observed_blocks: active.observed_blocks.clone(),
            period: active.period,
            repeats: active.repeats,
            state_delta: active.state_delta.clone(),
            phase_summaries: active.phase_summaries.clone(),
            phase_deltas: active.phase_deltas.clone(),
        })
    }

    pub(super) fn top_blocks(&self, limit: usize) -> Vec<((u64, u32), u64)> {
        let mut blocks = self
            .block_hits
            .iter()
            .map(|(&(pc, size), &hits)| ((pc, size), hits))
            .collect::<Vec<_>>();
        blocks.sort_by(|left, right| {
            right
                .1
                .cmp(&left.1)
                .then_with(|| left.0 .0.cmp(&right.0 .0))
                .then_with(|| left.0 .1.cmp(&right.0 .1))
        });
        blocks.truncate(limit);
        blocks
    }

    pub(super) fn update_loop_detection(&mut self) -> Option<NativeLoopSnapshot> {
        let Some(detected) = self.detect_repeating_loop() else {
            self.active_loop = None;
            return None;
        };

        match &mut self.active_loop {
            Some(active)
                if active.period == detected.period && active.blocks == detected.blocks =>
            {
                active.repeats = detected.repeats;
                active.observed_blocks = detected.observed_blocks.clone();
                active.state_delta = detected.state_delta.clone();
                active.phase_summaries = detected.phase_summaries.clone();
                active.phase_deltas = detected.phase_deltas.clone();
                if active.repeats < active.next_emit_repeats {
                    return None;
                }
                while active.next_emit_repeats <= active.repeats {
                    active.next_emit_repeats = active.next_emit_repeats.saturating_mul(2);
                }
                Some(NativeLoopSnapshot {
                    blocks: active.blocks.clone(),
                    observed_blocks: active.observed_blocks.clone(),
                    period: active.period,
                    repeats: active.repeats,
                    state_delta: active.state_delta.clone(),
                    phase_summaries: active.phase_summaries.clone(),
                    phase_deltas: active.phase_deltas.clone(),
                })
            }
            _ => {
                self.active_loop = Some(ActiveNativeLoop {
                    blocks: detected.blocks.clone(),
                    observed_blocks: detected.observed_blocks.clone(),
                    period: detected.period,
                    repeats: detected.repeats,
                    state_delta: detected.state_delta.clone(),
                    phase_summaries: detected.phase_summaries.clone(),
                    phase_deltas: detected.phase_deltas.clone(),
                    next_emit_repeats: detected.repeats.saturating_mul(2),
                });
                Some(detected)
            }
        }
    }

    pub(super) fn detect_repeating_loop(&mut self) -> Option<NativeLoopSnapshot> {
        let sequence = self.recent_sequence.make_contiguous();
        if sequence.len() < NATIVE_LOOP_MIN_PERIOD_BLOCKS * NATIVE_LOOP_MIN_REPEATS as usize {
            return None;
        }
        let max_period =
            NATIVE_LOOP_MAX_PERIOD_BLOCKS.min(sequence.len() / NATIVE_LOOP_MIN_REPEATS as usize);
        for period in NATIVE_LOOP_MIN_PERIOD_BLOCKS..=max_period {
            let pattern_start = sequence.len().saturating_sub(period);
            let pattern = &sequence[pattern_start..];
            let mut repeats = 1u64;
            while sequence.len() >= (repeats as usize + 1) * period {
                let start = sequence.len() - (repeats as usize + 1) * period;
                let end = start + period;
                if &sequence[start..end] != pattern {
                    break;
                }
                repeats = repeats.saturating_add(1);
            }
            if repeats >= NATIVE_LOOP_MIN_REPEATS {
                let observed_blocks = pattern.to_vec();
                return Some(NativeLoopSnapshot {
                    blocks: Self::canonicalize_loop_blocks(pattern),
                    observed_blocks: observed_blocks.clone(),
                    period,
                    repeats,
                    state_delta: self.current_loop_state_delta(&observed_blocks),
                    phase_summaries: self.current_loop_phase_summaries(&observed_blocks),
                    phase_deltas: self.current_loop_phase_deltas(&observed_blocks),
                });
            }
        }
        None
    }

    pub(super) fn current_loop_state_delta(
        &self,
        observed_blocks: &[(u64, u32)],
    ) -> Option<LoopStateDelta> {
        let pairs = self.current_loop_phase_pairs(observed_blocks)?;
        let (before, after) = pairs.first().copied()?;
        let state_delta = LoopStateDelta {
            registers: Self::diff_register_files(&before.registers, &after.registers),
            stack_words: Self::diff_named_values(&before.stack_words, &after.stack_words),
        };
        if state_delta.is_empty() {
            None
        } else {
            Some(state_delta)
        }
    }

    pub(super) fn diff_register_files(
        before: &RegisterFile,
        after: &RegisterFile,
    ) -> BTreeMap<String, LoopValueDelta> {
        let mut deltas = BTreeMap::new();
        before.for_each_nonzero(|name, before_value| {
            let after_value = after.get(name);
            if before_value != after_value {
                deltas.insert(
                    name.to_string(),
                    LoopValueDelta {
                        before: before_value,
                        after: after_value,
                    },
                );
            }
        });
        after.for_each_nonzero(|name, after_value| {
            let before_value = before.get(name);
            if before_value != after_value && !deltas.contains_key(name) {
                deltas.insert(
                    name.to_string(),
                    LoopValueDelta {
                        before: before_value,
                        after: after_value,
                    },
                );
            }
        });
        deltas
    }

    pub(super) fn diff_named_values(
        before: &BTreeMap<String, u64>,
        after: &BTreeMap<String, u64>,
    ) -> BTreeMap<String, LoopValueDelta> {
        let mut deltas = BTreeMap::new();
        for key in before.keys().chain(after.keys()) {
            let Some(before_value) = before.get(key).copied() else {
                continue;
            };
            let Some(after_value) = after.get(key).copied() else {
                continue;
            };
            if before_value == after_value {
                continue;
            }
            deltas.insert(
                key.clone(),
                LoopValueDelta {
                    before: before_value,
                    after: after_value,
                },
            );
        }
        deltas
    }

    pub(super) fn current_loop_phase_pairs<'a>(
        &'a self,
        observed_blocks: &[(u64, u32)],
    ) -> Option<Vec<(&'a NativeBlockSnapshot, &'a NativeBlockSnapshot)>> {
        let period = observed_blocks.len();
        if period == 0 || self.recent_snapshots.len() < period * 2 {
            return None;
        }
        let snapshots = self.recent_snapshots.iter().collect::<Vec<_>>();
        let previous = &snapshots[snapshots.len() - period * 2..snapshots.len() - period];
        let current = &snapshots[snapshots.len() - period..];
        if previous
            .iter()
            .map(|snapshot| (snapshot.pc, snapshot.size))
            .ne(observed_blocks.iter().copied())
        {
            return None;
        }
        if current
            .iter()
            .map(|snapshot| (snapshot.pc, snapshot.size))
            .ne(observed_blocks.iter().copied())
        {
            return None;
        }
        Some(
            previous
                .iter()
                .zip(current.iter())
                .map(|(before, after)| (*before, *after))
                .collect(),
        )
    }

    pub(super) fn current_loop_phase_summaries(
        &self,
        observed_blocks: &[(u64, u32)],
    ) -> Vec<LoopPhaseSummary> {
        let Some(pairs) = self.current_loop_phase_pairs(observed_blocks) else {
            return Vec::new();
        };
        pairs
            .into_iter()
            .enumerate()
            .map(|(phase, (before, after))| {
                let changed_registers =
                    Self::diff_register_files(&before.registers, &after.registers)
                        .into_keys()
                        .collect();
                let changed_stack_words =
                    Self::diff_named_values(&before.stack_words, &after.stack_words)
                        .into_keys()
                        .collect();
                LoopPhaseSummary {
                    phase,
                    pc: after.pc,
                    size: after.size,
                    changed_registers,
                    changed_stack_words,
                }
            })
            .collect()
    }

    pub(super) fn current_loop_phase_deltas(
        &self,
        observed_blocks: &[(u64, u32)],
    ) -> Vec<LoopPhaseDelta> {
        let Some(pairs) = self.current_loop_phase_pairs(observed_blocks) else {
            return Vec::new();
        };
        let mut phase_deltas = pairs
            .into_iter()
            .enumerate()
            .filter_map(|(phase, (before, after))| {
                let state_delta = LoopStateDelta {
                    registers: Self::diff_register_files(&before.registers, &after.registers),
                    stack_words: Self::diff_named_values(&before.stack_words, &after.stack_words),
                };
                if state_delta.is_empty() {
                    return None;
                }
                Some(LoopPhaseDelta {
                    phase,
                    pc: after.pc,
                    size: after.size,
                    state_delta,
                })
            })
            .collect::<Vec<_>>();

        phase_deltas.sort_by(|left, right| {
            right
                .change_count()
                .cmp(&left.change_count())
                .then_with(|| left.phase.cmp(&right.phase))
        });
        phase_deltas.truncate(NATIVE_LOOP_PHASE_DELTA_LIMIT);
        phase_deltas
    }

    pub(super) fn canonicalize_loop_blocks(blocks: &[(u64, u32)]) -> Vec<(u64, u32)> {
        if blocks.len() <= 1 {
            return blocks.to_vec();
        }
        let mut best = blocks.to_vec();
        for rotation in 1..blocks.len() {
            let mut candidate = Vec::with_capacity(blocks.len());
            candidate.extend_from_slice(&blocks[rotation..]);
            candidate.extend_from_slice(&blocks[..rotation]);
            if candidate < best {
                best = candidate;
            }
        }
        best
    }
}

impl Default for NativeTraceState {
    fn default() -> Self {
        Self {
            total_blocks: 0,
            block_hits: BTreeMap::new(),
            recent_sequence: VecDeque::new(),
            recent_snapshots: VecDeque::new(),
            active_loop: None,
            next_progress_instruction: NATIVE_PROGRESS_INTERVAL_INSTRUCTIONS,
        }
    }
}
