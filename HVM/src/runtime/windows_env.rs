use std::collections::{BTreeSet, HashMap};

use crate::arch::ArchSpec;
use crate::error::MemoryError;
use crate::memory::manager::{MemoryManager, PAGE_SIZE};
use crate::runtime::thread_context::ThreadContext;

mod core;
mod memory;
pub mod path_mapping;
mod process;
mod thread;

pub(crate) use core::layout::ldr_region_size_for_arch;
pub use core::layout::{ProcessEnvironmentLayout, ProcessEnvironmentOffsets};
use core::layout::{
    ENVIRONMENT_A_BUFFER_SIZE, ENVIRONMENT_W_BUFFER_SIZE, GDT_REGION_SIZE, PEB_REGION_SIZE,
    PROCESS_BUFFER_SIZE, PROCESS_PARAMETERS_REGION_SIZE, TEB_REGION_SIZE,
};

type EnvironmentPage = Box<[u8; PAGE_SIZE as usize]>;

#[derive(Debug, Clone, Copy)]
struct LoaderEntryAllocation {
    entry_base: u64,
    full_name_buffer: u64,
    full_name_reserved: u64,
    base_name_buffer: u64,
    base_name_reserved: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderAddressKind {
    Entry,
    FullDllNameBuffer,
    BaseDllNameBuffer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderAddressInfo {
    pub entry_base: u64,
    pub entry_index: usize,
    pub module_base: u64,
    pub module_name: String,
    pub full_name: String,
    pub kind: LoaderAddressKind,
}

/// Maintains a sparse pseudo-memory layout for PEB, TEB, and TLS mirrors.
#[derive(Debug)]
pub struct WindowsProcessEnvironment {
    arch: &'static ArchSpec,
    layout: ProcessEnvironmentLayout,
    offsets: ProcessEnvironmentOffsets,
    allocated_tls_slots: BTreeSet<usize>,
    memory: HashMap<u64, EnvironmentPage>,
    dirty: bool,
    dirty_pages: BTreeSet<u64>,
    current_teb_base: u64,
    thread_contexts: HashMap<u64, ThreadContext>,
    thread_tls_slots: HashMap<u64, u64>,
    loader_entries: HashMap<u64, LoaderEntryAllocation>,
    next_loader_cursor: u64,
    next_tls_slot: usize,
    next_teb_base: u64,
}
