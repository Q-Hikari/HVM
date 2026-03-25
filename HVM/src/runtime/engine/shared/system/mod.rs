use super::*;
use crate::managers::file_mapping_manager::{MappingSource, MappingViewRecord, MappingWriteTarget};
use crate::memory::manager::MemoryManager;
use crate::pe::loader::map_image;

#[derive(Debug, Clone, Copy)]
pub(in crate::runtime::engine) struct MemoryBasicInfoSnapshot {
    pub(in crate::runtime::engine) base_address: u64,
    pub(in crate::runtime::engine) allocation_base: u64,
    pub(in crate::runtime::engine) allocation_protect: u32,
    pub(in crate::runtime::engine) region_size: u64,
    pub(in crate::runtime::engine) state: u32,
    pub(in crate::runtime::engine) protect: u32,
    pub(in crate::runtime::engine) region_type: u32,
}

mod environment;
mod filesystem;
mod formatting;
mod memory_mapping;
mod process_launch;
mod processes;
mod thread_context;
mod virtual_memory;
mod waits;
