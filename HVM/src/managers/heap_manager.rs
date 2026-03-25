use std::collections::BTreeMap;

use crate::error::MemoryError;
use crate::memory::manager::{align_up, MemoryManager, PAGE_SIZE};

const HEAP_GROWABLE: u32 = 0x0000_0002;
const HEAP_ALLOCATION_GRANULARITY: u64 = 0x10;
const HEAP_SEGMENT_MIN_SIZE: u64 = 0x1_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapBlockRecord {
    pub requested_size: u64,
    pub allocation_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapSegmentRecord {
    pub base: u64,
    pub size: u64,
    pub committed: u64,
}

/// Stores one emulated heap plus the blocks currently allocated from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapRecord {
    pub handle: u32,
    pub base: u64,
    pub header_size: u64,
    pub blocks: BTreeMap<u64, HeapBlockRecord>,
    pub segments: Vec<HeapSegmentRecord>,
    free_ranges: BTreeMap<u64, u64>,
}

/// Mirrors the Python heap manager over the shared emulated memory manager.
#[derive(Debug)]
pub struct HeapManager {
    process_heap: u32,
    heaps: BTreeMap<u32, HeapRecord>,
}

impl HeapManager {
    /// Builds the heap manager and seeds the process heap header in emulated memory.
    pub fn new(memory: &mut MemoryManager) -> Result<Self, MemoryError> {
        let mut manager = Self {
            process_heap: 0,
            heaps: BTreeMap::new(),
        };
        let process_heap = manager.create_heap(memory)?;
        manager.process_heap = process_heap;
        Ok(manager)
    }

    /// Returns the current process heap handle.
    pub fn process_heap(&self) -> u32 {
        self.process_heap
    }

    /// Returns the current heap handle snapshot in creation order.
    pub fn snapshot(&self) -> Vec<u32> {
        self.heaps.keys().copied().collect()
    }

    /// Creates a new heap and initializes the same header fields as the Python baseline.
    pub fn create_heap(&mut self, memory: &mut MemoryManager) -> Result<u32, MemoryError> {
        let base = memory.reserve(PAGE_SIZE, None, "heap", false)?;
        let mut header = vec![0u8; PAGE_SIZE as usize];
        let (flags_offset, force_flags_offset) = (0x0Cusize, 0x10usize);
        header[flags_offset..flags_offset + 4].copy_from_slice(&HEAP_GROWABLE.to_le_bytes());
        header[force_flags_offset..force_flags_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        memory.write(base, &header)?;

        let handle = base as u32;
        self.heaps.insert(
            handle,
            HeapRecord {
                handle,
                base,
                header_size: PAGE_SIZE,
                blocks: BTreeMap::new(),
                segments: Vec::new(),
                free_ranges: BTreeMap::new(),
            },
        );
        Ok(handle)
    }

    /// Allocates one heap block and records its aligned size.
    pub fn alloc(
        &mut self,
        memory: &mut MemoryManager,
        heap_handle: u32,
        size: u64,
    ) -> Option<u64> {
        let heap = self.heaps.get_mut(&heap_handle)?;
        let requested = size.max(1);
        let actual = align_up(requested, HEAP_ALLOCATION_GRANULARITY);
        let address = Self::take_free_range(&mut heap.free_ranges, actual).or_else(|| {
            let segment = Self::active_segment(heap, memory, heap_handle, actual).ok()?;
            let address = segment.base + segment.committed;
            segment.committed = segment.committed.saturating_add(actual);
            Some(address)
        })?;
        heap.blocks.insert(
            address,
            HeapBlockRecord {
                requested_size: requested,
                allocation_size: actual,
            },
        );
        Some(address)
    }

    /// Frees a previously allocated heap block.
    pub fn free(&mut self, heap_handle: u32, address: u64) -> bool {
        let Some(heap) = self.heaps.get_mut(&heap_handle) else {
            return false;
        };
        let Some(block) = heap.blocks.remove(&address) else {
            return false;
        };
        Self::insert_free_range(&mut heap.free_ranges, address, block.allocation_size);
        true
    }

    /// Returns the recorded heap allocation size or `u32::MAX` on failure like Win32.
    pub fn size(&self, heap_handle: u32, address: u64) -> u64 {
        self.heaps
            .get(&heap_handle)
            .and_then(|heap| heap.blocks.get(&address))
            .map(|block| block.allocation_size)
            .unwrap_or(u32::MAX as u64)
    }

    /// Destroys a non-process heap and removes its mapped header.
    pub fn destroy(&mut self, memory: &mut MemoryManager, heap_handle: u32) -> bool {
        if heap_handle == self.process_heap {
            return false;
        }
        let Some(heap) = self.heaps.remove(&heap_handle) else {
            return false;
        };
        let _ = memory.unmap(heap.base, heap.header_size);
        for segment in heap.segments {
            let _ = memory.unmap(segment.base, segment.size);
        }
        true
    }

    fn active_segment<'a>(
        heap: &'a mut HeapRecord,
        memory: &mut MemoryManager,
        heap_handle: u32,
        requested: u64,
    ) -> Result<&'a mut HeapSegmentRecord, MemoryError> {
        let needs_segment = heap
            .segments
            .last()
            .map(|segment| segment.size.saturating_sub(segment.committed) < requested)
            .unwrap_or(true);
        if needs_segment {
            let segment_size = align_up(requested.max(HEAP_SEGMENT_MIN_SIZE), PAGE_SIZE);
            let base = memory.reserve(
                segment_size,
                None,
                &format!("heap:{heap_handle:#x}:segment"),
                false,
            )?;
            heap.segments.push(HeapSegmentRecord {
                base,
                size: segment_size,
                committed: 0,
            });
        }
        Ok(heap
            .segments
            .last_mut()
            .expect("heap segment must exist after growth"))
    }

    fn take_free_range(free_ranges: &mut BTreeMap<u64, u64>, requested: u64) -> Option<u64> {
        let (base, size) = free_ranges
            .iter()
            .find(|(_, size)| **size >= requested)
            .map(|(base, size)| (*base, *size))?;
        free_ranges.remove(&base);
        if size > requested {
            free_ranges.insert(base + requested, size - requested);
        }
        Some(base)
    }

    fn insert_free_range(free_ranges: &mut BTreeMap<u64, u64>, base: u64, size: u64) {
        let mut start = base;
        let mut end = base.saturating_add(size);
        if let Some((prev_base, prev_size)) = free_ranges
            .range(..=base)
            .next_back()
            .map(|(base, size)| (*base, *size))
        {
            let prev_end = prev_base.saturating_add(prev_size);
            if prev_end >= start {
                start = prev_base.min(start);
                end = end.max(prev_end);
                free_ranges.remove(&prev_base);
            }
        }
        loop {
            let Some((next_base, next_size)) = free_ranges
                .range(start..)
                .next()
                .map(|(base, size)| (*base, *size))
            else {
                break;
            };
            if next_base > end {
                break;
            }
            end = end.max(next_base.saturating_add(next_size));
            free_ranges.remove(&next_base);
        }
        free_ranges.insert(start, end.saturating_sub(start));
    }
}
