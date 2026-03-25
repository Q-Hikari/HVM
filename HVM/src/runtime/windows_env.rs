use std::collections::{BTreeMap, BTreeSet};

use crate::arch::ArchSpec;
use crate::error::MemoryError;
use crate::memory::manager::{MemoryManager, PAGE_SIZE};
use crate::runtime::thread_context::ThreadContext;

mod core;
mod memory;
mod process;
mod thread;

pub use core::layout::{ProcessEnvironmentLayout, ProcessEnvironmentOffsets};
use core::layout::{
    ENVIRONMENT_A_BUFFER_SIZE, ENVIRONMENT_W_BUFFER_SIZE, GDT_REGION_SIZE, LDR_REGION_SIZE,
    PEB_REGION_SIZE, PROCESS_BUFFER_SIZE, PROCESS_PARAMETERS_REGION_SIZE, TEB_REGION_SIZE,
};

/// Maintains a sparse pseudo-memory layout for PEB, TEB, and TLS mirrors.
#[derive(Debug)]
pub struct WindowsProcessEnvironment {
    arch: &'static ArchSpec,
    layout: ProcessEnvironmentLayout,
    offsets: ProcessEnvironmentOffsets,
    allocated_tls_slots: BTreeSet<usize>,
    memory: BTreeMap<u64, u8>,
    dirty: bool,
    dirty_pages: BTreeSet<u64>,
    current_teb_base: u64,
    thread_contexts: BTreeMap<u64, ThreadContext>,
    thread_tls_slots: BTreeMap<u64, u64>,
    next_tls_slot: usize,
    next_teb_base: u64,
}
