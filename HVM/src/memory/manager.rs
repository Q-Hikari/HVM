use std::collections::BTreeMap;

use smallvec::SmallVec;

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use crate::arch::{ArchSpec, X86_ARCH};
use crate::error::MemoryError;
use crate::runtime::unicorn::{
    UcEngine, UnicornApi, UC_PROT_EXEC as UC_NATIVE_PROT_EXEC, UC_PROT_READ as UC_NATIVE_PROT_READ,
    UC_PROT_WRITE as UC_NATIVE_PROT_WRITE,
};

/// Emulated page size (4 KB).
pub const PAGE_SIZE: u64 = 0x1000;

/// Read permission bit for emulated regions.
pub const PROT_READ: u32 = 0x1;

/// Write permission bit for emulated regions.
pub const PROT_WRITE: u32 = 0x2;

/// Execute permission bit for emulated regions.
pub const PROT_EXEC: u32 = 0x4;
const X86_LOW_FALLBACK_ALLOC_BASE: u64 = 0x1000_0000;
/// Captures one mapped memory region and its backing bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub perms: u32,
    pub tag: String,
    data: Option<Vec<u8>>,
}

impl MemoryRegion {
    /// Returns the exclusive end address of the region.
    pub fn end(&self) -> u64 {
        self.base + self.size
    }
}

/// Carries the allocation layout rules for one target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLayout {
    pub stack_base: u64,
    pub stack_size: u64,
    pub alloc_base: u64,
}

/// Tracks mapped regions, reservation history, and backing bytes for emulated memory.
#[derive(Debug)]
pub struct MemoryManager {
    layout: MemoryLayout,
    rng: StdRng,
    pub regions: BTreeMap<u64, MemoryRegion>,
    pub history: Vec<(u64, u64)>,
    native_backend: Option<NativeBackend>,
}

#[derive(Debug, Clone, Copy)]
struct NativeBackend {
    api: *const UnicornApi,
    handle: *mut UcEngine,
}

impl MemoryManager {
    /// Builds a test-friendly memory manager for one target architecture.
    pub fn for_arch(arch: &'static ArchSpec) -> Self {
        Self {
            layout: MemoryLayout {
                stack_base: arch.stack_base,
                stack_size: arch.stack_size,
                alloc_base: arch.alloc_base,
            },
            rng: StdRng::seed_from_u64(0xC0DE_C0DE),
            regions: BTreeMap::new(),
            history: Vec::new(),
            native_backend: None,
        }
    }

    /// Builds a test-friendly x86 memory manager.
    pub fn for_tests() -> Self {
        Self::for_arch(&X86_ARCH)
    }

    /// Returns the active memory-layout constants used for stack and allocation placement.
    pub fn layout(&self) -> MemoryLayout {
        self.layout
    }

    /// Overrides the reserved stack size while preserving the existing stack placement.
    pub fn set_stack_size(&mut self, stack_size: u64) {
        self.layout.stack_size = align_up(stack_size.max(PAGE_SIZE), PAGE_SIZE);
    }

    /// Returns whether the requested range is currently unmapped.
    pub fn is_free(&self, base: u64, size: u64, avoid_history: bool) -> bool {
        !self.overlaps_regions(base, size) && (!avoid_history || !self.overlaps_history(base, size))
    }

    /// Maps a new zeroed region at an exact address.
    pub fn map_region(
        &mut self,
        base: u64,
        size: u64,
        perms: u32,
        tag: &str,
    ) -> Result<u64, MemoryError> {
        let size = align_up(size, PAGE_SIZE);
        if self.overlaps_regions(base, size) {
            return Err(MemoryError::OverlappingRegion { base, size });
        }
        self.map_region_native(base, size, perms)?;
        self.regions.insert(
            base,
            MemoryRegion {
                base,
                size,
                perms,
                tag: tag.to_string(),
                data: self
                    .native_backend
                    .is_none()
                    .then(|| vec![0; size as usize]),
            },
        );
        let history_index = self.history.partition_point(|(start, _)| *start < base);
        self.history
            .insert(history_index, (base, base.saturating_add(size)));
        Ok(base)
    }

    /// Updates the protection flags for an exact region mapping.
    pub fn protect(&mut self, base: u64, size: u64, perms: u32) -> Result<(), MemoryError> {
        let start = base & !(PAGE_SIZE - 1);
        let aligned_size = align_up(size.max(1), PAGE_SIZE);
        let end = start.saturating_add(aligned_size);

        // Collect overlapping regions: those whose base < end AND whose end > start.
        let keys: Vec<u64> = self
            .regions
            .range(..end)
            .filter(|(_, r)| r.end() > start)
            .map(|(k, _)| *k)
            .collect();

        if keys.is_empty() {
            return Err(MemoryError::MissingRegion {
                address: start,
                size: aligned_size,
            });
        }

        // Remove old regions, collect them for slicing.
        let mut old: Vec<MemoryRegion> = Vec::with_capacity(keys.len());
        for key in &keys {
            old.push(self.regions.remove(key).expect("key came from iterator"));
        }

        // Build replacement regions from the splice plan.
        let mut cursor = start;
        let mut region_idx = 0;
        while cursor < end {
            let region = old.get(region_idx).ok_or(MemoryError::MissingRegion {
                address: cursor,
                size: end.saturating_sub(cursor),
            })?;
            if cursor < region.base {
                return Err(MemoryError::MissingRegion {
                    address: cursor,
                    size: end.saturating_sub(cursor),
                });
            }
            let overlap_start = cursor.max(region.base);
            let overlap_end = region.end().min(end);
            if overlap_start >= overlap_end {
                return Err(MemoryError::MissingRegion {
                    address: cursor,
                    size: end.saturating_sub(cursor),
                });
            }
            if overlap_start > region.base {
                let sliced = Self::slice_region(region, region.base, overlap_start, region.perms);
                self.regions.insert(sliced.base, sliced);
            }
            let sliced = Self::slice_region(region, overlap_start, overlap_end, perms);
            self.regions.insert(sliced.base, sliced);
            if overlap_end < region.end() {
                let sliced = Self::slice_region(region, overlap_end, region.end(), region.perms);
                self.regions.insert(sliced.base, sliced);
            }
            cursor = overlap_end;
            region_idx += 1;
        }

        self.protect_region_native(start, aligned_size, perms)?;
        Ok(())
    }

    /// Removes an exact region mapping from the table.
    pub fn unmap(&mut self, base: u64, size: u64) -> Result<(), MemoryError> {
        let start = base & !(PAGE_SIZE - 1);
        let aligned_size = align_up(size.max(1), PAGE_SIZE);
        let end = start.saturating_add(aligned_size);

        // Collect overlapping regions: those whose base < end AND whose end > start.
        let keys: Vec<u64> = self
            .regions
            .range(..end)
            .filter(|(_, r)| r.end() > start)
            .map(|(k, _)| *k)
            .collect();

        if keys.is_empty() {
            return Err(MemoryError::MissingRegion {
                address: start,
                size: aligned_size,
            });
        }

        // Remove old regions, collect them for slicing.
        let mut old: Vec<MemoryRegion> = Vec::with_capacity(keys.len());
        for key in &keys {
            old.push(self.regions.remove(key).expect("key came from iterator"));
        }

        // Build replacement regions (keep non-overlapping head/tail).
        let mut cursor = start;
        let mut region_idx = 0;
        while cursor < end {
            let region = old.get(region_idx).ok_or(MemoryError::MissingRegion {
                address: cursor,
                size: end.saturating_sub(cursor),
            })?;
            if cursor < region.base {
                return Err(MemoryError::MissingRegion {
                    address: cursor,
                    size: end.saturating_sub(cursor),
                });
            }
            let overlap_start = cursor.max(region.base);
            let overlap_end = region.end().min(end);
            if overlap_start >= overlap_end {
                return Err(MemoryError::MissingRegion {
                    address: cursor,
                    size: end.saturating_sub(cursor),
                });
            }
            if overlap_start > region.base {
                let sliced = Self::slice_region(region, region.base, overlap_start, region.perms);
                self.regions.insert(sliced.base, sliced);
            }
            if overlap_end < region.end() {
                let sliced = Self::slice_region(region, overlap_end, region.end(), region.perms);
                self.regions.insert(sliced.base, sliced);
            }
            cursor = overlap_end;
            region_idx += 1;
        }

        self.unmap_region_native(start, aligned_size)?;
        Ok(())
    }

    /// Reserves a writable, readable, executable region, preferring the requested base when possible.
    pub fn reserve(
        &mut self,
        size: u64,
        preferred: Option<u64>,
        tag: &str,
        avoid_history: bool,
    ) -> Result<u64, MemoryError> {
        let size = align_up(size, PAGE_SIZE);
        if let Some(preferred) = preferred {
            let preferred = align_up(preferred, PAGE_SIZE);
            if self.is_free(preferred, size, false) {
                return self.map_region(preferred, size, PROT_READ | PROT_WRITE | PROT_EXEC, tag);
            }
        }
        let probe = align_up(self.layout.alloc_base, PAGE_SIZE);
        let alloc_span = self.allocation_span();
        let slots = alloc_span / PAGE_SIZE;
        for _ in 0..0x20_000 {
            let candidate = probe + (self.rng.next_u64() % slots) * PAGE_SIZE;
            if self.is_free(candidate, size, avoid_history) {
                return self.map_region(candidate, size, PROT_READ | PROT_WRITE | PROT_EXEC, tag);
            }
        }
        let mut candidate = probe;
        let limit = probe.saturating_add(alloc_span.saturating_sub(size));
        while candidate <= limit {
            if self.is_free(candidate, size, avoid_history) {
                return self.map_region(candidate, size, PROT_READ | PROT_WRITE | PROT_EXEC, tag);
            }
            let next = candidate.saturating_add(PAGE_SIZE);
            if next <= candidate {
                break;
            }
            candidate = next;
        }
        if self.layout.alloc_base <= u32::MAX as u64
            && X86_LOW_FALLBACK_ALLOC_BASE < self.layout.alloc_base
        {
            let mut candidate = align_up(X86_LOW_FALLBACK_ALLOC_BASE, PAGE_SIZE);
            let limit = self.layout.alloc_base.saturating_sub(size);
            while candidate <= limit {
                if self.is_free(candidate, size, avoid_history) {
                    return self.map_region(
                        candidate,
                        size,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        tag,
                    );
                }
                let next = candidate.saturating_add(PAGE_SIZE);
                if next <= candidate {
                    break;
                }
                candidate = next;
            }
        }
        Err(MemoryError::OutOfMemory {
            size,
            tag: Some(tag.to_string()),
            preferred,
            avoid_history: Some(avoid_history),
        })
    }

    /// Allocates the primary stack using the default x86 placement.
    pub fn allocate_stack(&mut self) -> Result<(u64, u64), MemoryError> {
        let base = self.layout.stack_base - self.layout.stack_size;
        if self.is_free(base, self.layout.stack_size, false) {
            self.map_region(
                base,
                self.layout.stack_size,
                PROT_READ | PROT_WRITE,
                "stack",
            )?;
            return Ok((base, base + self.layout.stack_size - PAGE_SIZE));
        }
        let stack_base = self.reserve(self.layout.stack_size, None, "stack", false)?;
        Ok((stack_base, stack_base + self.layout.stack_size - PAGE_SIZE))
    }

    /// Finds the mapped region that fully contains the requested range.
    pub fn find_region(&self, address: u64, size: u64) -> Option<&MemoryRegion> {
        let end = address.checked_add(size.max(1))?;
        let region = self.regions.range(..=address).next_back()?.1;
        if end <= region.end() {
            Some(region)
        } else {
            None
        }
    }

    /// Returns whether adjacent mapped regions fully cover the requested range.
    pub fn is_range_mapped(&self, address: u64, size: u64) -> bool {
        self.range_chunks(address, size.max(1)).is_ok()
    }

    /// Writes bytes into a mapped region.
    pub fn write(&mut self, address: u64, data: &[u8]) -> Result<(), MemoryError> {
        let chunks = self.range_chunks(address, (data.len() as u64).max(1))?;
        self.write_native(address, data)?;
        let mut written = 0usize;
        for (key, offset, chunk_len) in chunks {
            if written >= data.len() {
                break;
            }
            let copy_len = chunk_len.min(data.len() - written);
            let region = self
                .regions
                .get_mut(&key)
                .ok_or(MemoryError::MissingRegion {
                    address,
                    size: (data.len() as u64).max(1),
                })?;
            if let Some(backing) = region.data.as_mut() {
                backing[offset..offset + copy_len]
                    .copy_from_slice(&data[written..written + copy_len]);
            }
            written += copy_len;
        }
        Ok(())
    }

    /// Updates the local mirror for bytes that were already written by the native backend.
    pub fn write_mirror(&mut self, address: u64, data: &[u8]) -> Result<(), MemoryError> {
        let chunks = self.range_chunks(address, (data.len() as u64).max(1))?;
        let mut written = 0usize;
        for (key, offset, chunk_len) in chunks {
            if written >= data.len() {
                break;
            }
            let copy_len = chunk_len.min(data.len() - written);
            let region = self
                .regions
                .get_mut(&key)
                .ok_or(MemoryError::MissingRegion {
                    address,
                    size: (data.len() as u64).max(1),
                })?;
            if let Some(backing) = region.data.as_mut() {
                backing[offset..offset + copy_len]
                    .copy_from_slice(&data[written..written + copy_len]);
            }
            written += copy_len;
        }
        Ok(())
    }

    /// Fast path for native write-back when the caller already knows the range
    /// fits entirely inside one mapped region.
    pub fn write_mirror_contiguous(
        &mut self,
        address: u64,
        data: &[u8],
    ) -> Result<(), MemoryError> {
        let size = (data.len() as u64).max(1);
        let end = address
            .checked_add(size)
            .ok_or(MemoryError::MissingRegion { address, size })?;
        let key = self
            .regions
            .range(..=address)
            .next_back()
            .map(|(k, _)| *k)
            .ok_or(MemoryError::MissingRegion { address, size })?;
        let region = self
            .regions
            .get_mut(&key)
            .ok_or(MemoryError::MissingRegion { address, size })?;
        if end > region.end() {
            return Err(MemoryError::MissingRegion { address, size });
        }
        if let Some(backing) = region.data.as_mut() {
            let offset = (address - region.base) as usize;
            backing[offset..offset + data.len()].copy_from_slice(data);
        }
        Ok(())
    }

    /// Reads bytes from a mapped region.
    pub fn read(&self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        if let Some(backend) = self.native_backend {
            let api = unsafe { &*backend.api };
            let unicorn = unsafe { api.bind(backend.handle) };
            let mut bytes = vec![0u8; size];
            unicorn
                .mem_read_into(address, &mut bytes)
                .map_err(|detail| MemoryError::NativeBackend {
                    op: "uc_mem_read",
                    detail,
                })?;
            return Ok(bytes);
        }
        let chunks = self.range_chunks(address, (size as u64).max(1))?;
        let mut bytes = Vec::with_capacity(size);
        let mut remaining = size;
        for (key, offset, chunk_len) in chunks {
            if remaining == 0 {
                break;
            }
            let copy_len = chunk_len.min(remaining);
            let region = self.regions.get(&key).ok_or(MemoryError::MissingRegion {
                address,
                size: (size as u64).max(1),
            })?;
            let backing = region.data.as_ref().ok_or(MemoryError::MissingRegion {
                address,
                size: (size as u64).max(1),
            })?;
            bytes.extend_from_slice(&backing[offset..offset + copy_len]);
            remaining -= copy_len;
        }
        Ok(bytes)
    }

    /// Reads one fixed-size byte array without going through a heap allocation.
    pub fn read_fixed<const N: usize>(&self, address: u64) -> Result<[u8; N], MemoryError> {
        if let Some(backend) = self.native_backend {
            let api = unsafe { &*backend.api };
            let unicorn = unsafe { api.bind(backend.handle) };
            let mut bytes = [0u8; N];
            unicorn
                .mem_read_into(address, &mut bytes)
                .map_err(|detail| MemoryError::NativeBackend {
                    op: "uc_mem_read",
                    detail,
                })?;
            return Ok(bytes);
        }
        let mut bytes = [0u8; N];
        let chunks = self.range_chunks(address, (N as u64).max(1))?;
        let mut read = 0usize;
        for (key, offset, chunk_len) in chunks {
            if read >= N {
                break;
            }
            let copy_len = chunk_len.min(N - read);
            let region = self.regions.get(&key).ok_or(MemoryError::MissingRegion {
                address,
                size: (N as u64).max(1),
            })?;
            let backing = region.data.as_ref().ok_or(MemoryError::MissingRegion {
                address,
                size: (N as u64).max(1),
            })?;
            bytes[read..read + copy_len].copy_from_slice(&backing[offset..offset + copy_len]);
            read += copy_len;
        }
        Ok(bytes)
    }

    /// Reads one little-endian u8.
    pub fn read_u8(&self, address: u64) -> Result<u8, MemoryError> {
        Ok(self.read_fixed::<1>(address)?[0])
    }

    /// Reads one little-endian u16.
    pub fn read_u16(&self, address: u64) -> Result<u16, MemoryError> {
        Ok(u16::from_le_bytes(self.read_fixed::<2>(address)?))
    }

    /// Reads one little-endian u32.
    pub fn read_u32(&self, address: u64) -> Result<u32, MemoryError> {
        Ok(u32::from_le_bytes(self.read_fixed::<4>(address)?))
    }

    /// Attaches a live Unicorn backend so subsequent memory operations hit native state directly.
    pub fn attach_native(&mut self, api: *const UnicornApi, handle: *mut UcEngine) {
        self.native_backend = Some(NativeBackend { api, handle });
        // Once Unicorn owns the authoritative guest memory, drop the Rust-side mirror to avoid
        // keeping a second full copy of every mapped region in RSS.
        for region in self.regions.values_mut() {
            region.data = None;
        }
    }

    /// Detaches any live Unicorn backend and falls back to the local mirror only.
    pub fn detach_native(&mut self) {
        self.native_backend = None;
    }

    fn overlaps_regions(&self, base: u64, size: u64) -> bool {
        let end = base.saturating_add(size);
        // Check the region at or just after `base`.
        if self
            .regions
            .range(base..)
            .next()
            .map(|(_, r)| r.base < end)
            .unwrap_or(false)
        {
            return true;
        }
        // Check the region just before `base` — it may extend past `base`.
        self.regions
            .range(..base)
            .next_back()
            .map(|(_, r)| base < r.end())
            .unwrap_or(false)
    }

    fn overlaps_history(&self, base: u64, size: u64) -> bool {
        let end = base.saturating_add(size);
        // history is sorted by base — use binary search to find the starting point
        let idx = self
            .history
            .partition_point(|(other_base, _)| *other_base < base);
        // Check the entry just before (its range may extend past our base)
        if idx > 0 {
            let (prev_base, prev_end) = &self.history[idx - 1];
            if base < *prev_end && *prev_base < end {
                return true;
            }
        }
        // Check entries at or after the starting point until their base >= our end
        for (other_base, other_end) in &self.history[idx..] {
            if *other_base >= end {
                break;
            }
            if base < *other_end {
                return true;
            }
        }
        false
    }

    fn range_chunks(
        &self,
        address: u64,
        size: u64,
    ) -> Result<SmallVec<[(u64, usize, usize); 4]>, MemoryError> {
        let end = address
            .checked_add(size)
            .ok_or(MemoryError::MissingRegion { address, size })?;
        let mut chunks = SmallVec::new();
        let mut cursor = address;
        while cursor < end {
            let (&key, region) = self
                .regions
                .range(..=cursor)
                .next_back()
                .ok_or(MemoryError::MissingRegion { address, size })?;
            if cursor < region.base {
                return Err(MemoryError::MissingRegion { address, size });
            }
            let chunk_end = end.min(region.end());
            if chunk_end <= cursor {
                return Err(MemoryError::MissingRegion { address, size });
            }
            chunks.push((
                key,
                (cursor - region.base) as usize,
                (chunk_end - cursor) as usize,
            ));
            cursor = chunk_end;
        }
        Ok(chunks)
    }

    fn allocation_span(&self) -> u64 {
        if self.layout.alloc_base > u32::MAX as u64 {
            0x1_0000_0000
        } else {
            0x20_000_000
        }
    }

    fn slice_region(region: &MemoryRegion, start: u64, end: u64, perms: u32) -> MemoryRegion {
        let offset = (start - region.base) as usize;
        let size = (end - start) as usize;
        MemoryRegion {
            base: start,
            size: size as u64,
            perms,
            tag: region.tag.clone(),
            data: region
                .data
                .as_ref()
                .map(|backing| backing[offset..offset + size].to_vec()),
        }
    }

    fn write_native(&self, address: u64, data: &[u8]) -> Result<(), MemoryError> {
        let Some(backend) = self.native_backend else {
            return Ok(());
        };
        let api = unsafe { &*backend.api };
        let unicorn = unsafe { api.bind(backend.handle) };
        unicorn
            .mem_write(address, data)
            .map_err(|detail| MemoryError::NativeBackend {
                op: "uc_mem_write",
                detail,
            })
    }

    fn map_region_native(&self, base: u64, size: u64, perms: u32) -> Result<(), MemoryError> {
        let Some(backend) = self.native_backend else {
            return Ok(());
        };
        let api = unsafe { &*backend.api };
        let unicorn = unsafe { api.bind(backend.handle) };
        unicorn
            .mem_map(base, size, unicorn_prot(perms))
            .map_err(|detail| MemoryError::NativeBackend {
                op: "uc_mem_map",
                detail,
            })
    }

    fn protect_region_native(&self, base: u64, size: u64, perms: u32) -> Result<(), MemoryError> {
        let Some(backend) = self.native_backend else {
            return Ok(());
        };
        let api = unsafe { &*backend.api };
        let unicorn = unsafe { api.bind(backend.handle) };
        unicorn
            .mem_protect(base, size, unicorn_prot(perms))
            .map_err(|detail| MemoryError::NativeBackend {
                op: "uc_mem_protect",
                detail,
            })
    }

    fn unmap_region_native(&self, base: u64, size: u64) -> Result<(), MemoryError> {
        let Some(backend) = self.native_backend else {
            return Ok(());
        };
        let api = unsafe { &*backend.api };
        let unicorn = unsafe { api.bind(backend.handle) };
        unicorn
            .mem_unmap(base, size)
            .map_err(|detail| MemoryError::NativeBackend {
                op: "uc_mem_unmap",
                detail,
            })
    }
}

fn unicorn_prot(perms: u32) -> u32 {
    let mut mapped = 0;
    if perms & PROT_READ != 0 {
        mapped |= UC_NATIVE_PROT_READ;
    }
    if perms & PROT_WRITE != 0 {
        mapped |= UC_NATIVE_PROT_WRITE;
    }
    if perms & PROT_EXEC != 0 {
        mapped |= UC_NATIVE_PROT_EXEC;
    }
    mapped
}

/// Aligns a value upward to the requested boundary.
pub fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    #[test]
    fn protect_splits_regions_for_subrange_updates() {
        let mut memory = super::MemoryManager::for_tests();
        let base = memory
            .map_region(
                0x1000_0000,
                0x3000,
                super::PROT_READ | super::PROT_WRITE,
                "protect",
            )
            .unwrap();
        memory.write(base + 0x1000, b"split").unwrap();

        memory
            .protect(base + 0x1000, 0x1000, super::PROT_READ)
            .unwrap();

        let regions: Vec<&super::MemoryRegion> = memory.regions.values().collect();
        assert_eq!(regions.len(), 3);
        assert_eq!(regions[0].base, base);
        assert_eq!(regions[0].size, 0x1000);
        assert_eq!(regions[0].perms, super::PROT_READ | super::PROT_WRITE);
        assert_eq!(regions[1].base, base + 0x1000);
        assert_eq!(regions[1].size, 0x1000);
        assert_eq!(regions[1].perms, super::PROT_READ);
        assert_eq!(regions[2].base, base + 0x2000);
        assert_eq!(regions[2].size, 0x1000);
        assert_eq!(regions[2].perms, super::PROT_READ | super::PROT_WRITE);
        assert_eq!(memory.read(base + 0x1000, 5).unwrap(), b"split");
    }

    #[test]
    fn range_mapping_and_reads_span_adjacent_split_regions() {
        let mut memory = super::MemoryManager::for_tests();
        let base = memory
            .map_region(
                0x1800_0000,
                0x3000,
                super::PROT_READ | super::PROT_WRITE,
                "span",
            )
            .unwrap();
        let write_base = base + 0x0ff8;
        let payload = *b"cross-region-span";

        memory
            .protect(base + 0x1000, 0x1000, super::PROT_READ)
            .unwrap();

        assert!(memory.find_region(base, 0x3000).is_none());
        assert!(memory.is_range_mapped(base, 0x3000));

        memory.write(write_base, &payload).unwrap();
        assert_eq!(memory.read(write_base, payload.len()).unwrap(), payload);
        assert_eq!(memory.read_fixed::<4>(base + 0x0ffe).unwrap(), *b"regi");
    }

    #[test]
    fn unmap_removes_ranges_after_region_splitting() {
        let mut memory = super::MemoryManager::for_tests();
        let base = memory
            .map_region(
                0x2000_0000,
                0x3000,
                super::PROT_READ | super::PROT_WRITE,
                "unmap",
            )
            .unwrap();

        memory
            .protect(base + 0x1000, 0x1000, super::PROT_READ)
            .unwrap();
        assert_eq!(memory.regions.len(), 3);

        memory.unmap(base, 0x3000).unwrap();
        assert!(memory.regions.is_empty());
    }

    #[test]
    fn x86_reserve_window_matches_default_span() {
        let memory = super::MemoryManager::for_tests();
        assert_eq!(memory.allocation_span(), 0x20_000_000);
    }

    #[test]
    fn x64_reserve_window_expands_beyond_legacy_512mb_span() {
        let memory = super::MemoryManager::for_arch(&crate::arch::X64_ARCH);
        assert_eq!(memory.allocation_span(), 0x1_0000_0000);
    }

    #[test]
    fn x86_reserve_falls_back_below_primary_high_arena() {
        let mut memory = super::MemoryManager::for_tests();
        memory.regions.insert(
            memory.layout.alloc_base,
            super::MemoryRegion {
                base: memory.layout.alloc_base,
                size: memory.allocation_span(),
                perms: super::PROT_READ,
                tag: "occupied-high-arena".to_string(),
                data: None,
            },
        );

        let reserved = memory
            .reserve(super::PAGE_SIZE, None, "fallback", false)
            .expect("x86 reserve should fall back into the lower arena");

        assert!(reserved >= super::X86_LOW_FALLBACK_ALLOC_BASE);
        assert!(reserved < memory.layout.alloc_base);
    }

    #[test]
    fn attach_native_releases_local_region_backing() {
        let mut memory = super::MemoryManager::for_tests();
        let base = memory
            .map_region(
                0x2000,
                super::PAGE_SIZE,
                super::PROT_READ | super::PROT_WRITE,
                "backed",
            )
            .unwrap();
        memory.write(base, &[0x41, 0x42, 0x43]).unwrap();
        assert!(memory.regions.get(&0x2000).unwrap().data.is_some());

        memory.attach_native(std::ptr::null(), std::ptr::null_mut());

        assert!(memory
            .regions
            .iter()
            .all(|(_, region)| region.data.is_none()));
    }
}
