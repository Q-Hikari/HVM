use crate::arch::{ArchSpec, X86_ARCH};
use crate::error::MemoryError;
use crate::runtime::unicorn::{
    UcEngine, UnicornApi, UC_PROT_EXEC as UC_NATIVE_PROT_EXEC, UC_PROT_READ as UC_NATIVE_PROT_READ,
    UC_PROT_WRITE as UC_NATIVE_PROT_WRITE,
};

/// Matches the emulated page size used by the Python memory manager.
pub const PAGE_SIZE: u64 = 0x1000;

/// Read permission bit for emulated regions.
pub const PROT_READ: u32 = 0x1;

/// Write permission bit for emulated regions.
pub const PROT_WRITE: u32 = 0x2;

/// Execute permission bit for emulated regions.
pub const PROT_EXEC: u32 = 0x4;

const MT_N: usize = 624;
const MT_M: usize = 397;
const MT_MATRIX_A: u32 = 0x9908_B0DF;
const MT_UPPER_MASK: u32 = 0x8000_0000;
const MT_LOWER_MASK: u32 = 0x7FFF_FFFF;

#[derive(Debug, Clone)]
struct PythonMt19937 {
    state: [u32; MT_N],
    index: usize,
}

impl PythonMt19937 {
    fn new(seed: u32) -> Self {
        let mut rng = Self {
            state: [0; MT_N],
            index: MT_N,
        };
        rng.init_by_array(&[seed]);
        rng
    }

    fn init_genrand(&mut self, seed: u32) {
        self.state[0] = seed;
        for i in 1..MT_N {
            let previous = self.state[i - 1];
            self.state[i] = 1_812_433_253u32
                .wrapping_mul(previous ^ (previous >> 30))
                .wrapping_add(i as u32);
        }
        self.index = MT_N;
    }

    fn init_by_array(&mut self, init_key: &[u32]) {
        self.init_genrand(19_650_218);
        let mut i = 1usize;
        let mut j = 0usize;
        let mut k = MT_N.max(init_key.len());
        while k > 0 {
            let previous = self.state[i - 1];
            self.state[i] = (self.state[i] ^ (previous ^ (previous >> 30)).wrapping_mul(1_664_525))
                .wrapping_add(init_key[j])
                .wrapping_add(j as u32);
            i += 1;
            j += 1;
            if i >= MT_N {
                self.state[0] = self.state[MT_N - 1];
                i = 1;
            }
            if j >= init_key.len() {
                j = 0;
            }
            k -= 1;
        }
        k = MT_N - 1;
        while k > 0 {
            let previous = self.state[i - 1];
            self.state[i] = (self.state[i]
                ^ (previous ^ (previous >> 30)).wrapping_mul(1_566_083_941))
            .wrapping_sub(i as u32);
            i += 1;
            if i >= MT_N {
                self.state[0] = self.state[MT_N - 1];
                i = 1;
            }
            k -= 1;
        }
        self.state[0] = 0x8000_0000;
        self.index = MT_N;
    }

    fn next_u32(&mut self) -> u32 {
        if self.index >= MT_N {
            self.twist();
        }
        let mut value = self.state[self.index];
        self.index += 1;
        value ^= value >> 11;
        value ^= (value << 7) & 0x9D2C_5680;
        value ^= (value << 15) & 0xEFC6_0000;
        value ^= value >> 18;
        value
    }

    fn getrandbits(&mut self, bits: u32) -> u64 {
        if bits == 0 {
            return 0;
        }
        if bits <= 32 {
            return (self.next_u32() >> (32 - bits)) as u64;
        }
        let words = ((bits - 1) / 32) + 1;
        let mut result = 0u64;
        for word_index in 0..words {
            let chunk_bits = if word_index == 0 {
                bits - 32 * (words - 1)
            } else {
                32
            };
            let mut chunk = self.next_u32();
            if chunk_bits < 32 {
                chunk >>= 32 - chunk_bits;
            }
            result = (result << chunk_bits) | chunk as u64;
        }
        result
    }

    fn rand_below(&mut self, upper_bound: u64) -> u64 {
        debug_assert!(upper_bound > 0);
        let bits = u64::BITS - upper_bound.leading_zeros();
        loop {
            let candidate = self.getrandbits(bits);
            if candidate < upper_bound {
                return candidate;
            }
        }
    }

    fn twist(&mut self) {
        for index in 0..(MT_N - MT_M) {
            let value =
                (self.state[index] & MT_UPPER_MASK) | (self.state[index + 1] & MT_LOWER_MASK);
            self.state[index] = self.state[index + MT_M]
                ^ (value >> 1)
                ^ if value & 1 != 0 { MT_MATRIX_A } else { 0 };
        }
        for index in (MT_N - MT_M)..(MT_N - 1) {
            let value =
                (self.state[index] & MT_UPPER_MASK) | (self.state[index + 1] & MT_LOWER_MASK);
            self.state[index] = self.state[index + MT_M - MT_N]
                ^ (value >> 1)
                ^ if value & 1 != 0 { MT_MATRIX_A } else { 0 };
        }
        let value = (self.state[MT_N - 1] & MT_UPPER_MASK) | (self.state[0] & MT_LOWER_MASK);
        self.state[MT_N - 1] =
            self.state[MT_M - 1] ^ (value >> 1) ^ if value & 1 != 0 { MT_MATRIX_A } else { 0 };
        self.index = 0;
    }
}

/// Captures one mapped memory region and its backing bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub perms: u32,
    pub tag: String,
    data: Vec<u8>,
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
    rng: PythonMt19937,
    pub regions: Vec<MemoryRegion>,
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
            rng: PythonMt19937::new(0xC0DE_C0DE),
            regions: Vec::new(),
            history: Vec::new(),
            native_backend: None,
        }
    }

    /// Builds a test-friendly x86 memory manager that mirrors the Python defaults.
    pub fn for_tests() -> Self {
        Self::for_arch(&X86_ARCH)
    }

    /// Returns the active memory-layout constants used for stack and allocation placement.
    pub fn layout(&self) -> MemoryLayout {
        self.layout
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
        let index = self.insert_index(base);
        self.regions.insert(
            index,
            MemoryRegion {
                base,
                size,
                perms,
                tag: tag.to_string(),
                data: vec![0; size as usize],
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
        let size = align_up(size.max(1), PAGE_SIZE);
        let end = start.saturating_add(size);
        let mut index = self
            .region_index_for_address(start)
            .unwrap_or_else(|| self.insert_index(start));
        if self
            .regions
            .get(index)
            .map(|region| start >= region.end())
            .unwrap_or(false)
        {
            index += 1;
        }
        let first = index;
        let mut cursor = start;
        let mut replacement = Vec::new();

        while cursor < end {
            let region = self.regions.get(index).ok_or(MemoryError::MissingRegion {
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
                replacement.push(Self::slice_region(
                    region,
                    region.base,
                    overlap_start,
                    region.perms,
                ));
            }
            replacement.push(Self::slice_region(
                region,
                overlap_start,
                overlap_end,
                perms,
            ));
            if overlap_end < region.end() {
                replacement.push(Self::slice_region(
                    region,
                    overlap_end,
                    region.end(),
                    region.perms,
                ));
            }
            cursor = overlap_end;
            index += 1;
        }

        self.protect_region_native(start, size, perms)?;
        self.regions.splice(first..index, replacement);
        Ok(())
    }

    /// Removes an exact region mapping from the table.
    pub fn unmap(&mut self, base: u64, size: u64) -> Result<(), MemoryError> {
        let start = base & !(PAGE_SIZE - 1);
        let size = align_up(size.max(1), PAGE_SIZE);
        let end = start.saturating_add(size);
        let mut index = self
            .region_index_for_address(start)
            .unwrap_or_else(|| self.insert_index(start));
        if self
            .regions
            .get(index)
            .map(|region| start >= region.end())
            .unwrap_or(false)
        {
            index += 1;
        }
        let first = index;
        let mut cursor = start;
        let mut replacement = Vec::new();

        while cursor < end {
            let region = self.regions.get(index).ok_or(MemoryError::MissingRegion {
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
            if region.base < overlap_start {
                replacement.push(Self::slice_region(
                    region,
                    region.base,
                    overlap_start,
                    region.perms,
                ));
            }
            if overlap_end < region.end() {
                replacement.push(Self::slice_region(
                    region,
                    overlap_end,
                    region.end(),
                    region.perms,
                ));
            }
            cursor = overlap_end;
            index += 1;
        }

        self.unmap_region_native(start, size)?;
        self.regions.splice(first..index, replacement);
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
            let candidate = probe + self.rng.rand_below(slots) * PAGE_SIZE;
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
        Err(MemoryError::OutOfMemory { size })
    }

    /// Allocates the primary stack using the Python x86 default placement when available.
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
        let index = self.region_index_for_address(address)?;
        let region = self.regions.get(index)?;
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
        for (index, offset, chunk_len) in chunks {
            if written >= data.len() {
                break;
            }
            let copy_len = chunk_len.min(data.len() - written);
            let region = self
                .regions
                .get_mut(index)
                .ok_or(MemoryError::MissingRegion {
                    address,
                    size: (data.len() as u64).max(1),
                })?;
            region.data[offset..offset + copy_len]
                .copy_from_slice(&data[written..written + copy_len]);
            written += copy_len;
        }
        Ok(())
    }

    /// Updates the local mirror for bytes that were already written by the native backend.
    pub fn write_mirror(&mut self, address: u64, data: &[u8]) -> Result<(), MemoryError> {
        let chunks = self.range_chunks(address, (data.len() as u64).max(1))?;
        let mut written = 0usize;
        for (index, offset, chunk_len) in chunks {
            if written >= data.len() {
                break;
            }
            let copy_len = chunk_len.min(data.len() - written);
            let region = self
                .regions
                .get_mut(index)
                .ok_or(MemoryError::MissingRegion {
                    address,
                    size: (data.len() as u64).max(1),
                })?;
            region.data[offset..offset + copy_len]
                .copy_from_slice(&data[written..written + copy_len]);
            written += copy_len;
        }
        Ok(())
    }

    /// Reads bytes from a mapped region.
    pub fn read(&self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        if let Some(backend) = self.native_backend {
            let api = unsafe { &*backend.api };
            let mut bytes = vec![0u8; size];
            unsafe { api.mem_read_into_raw(backend.handle, address, &mut bytes) }.map_err(
                |detail| MemoryError::NativeBackend {
                    op: "uc_mem_read",
                    detail,
                },
            )?;
            return Ok(bytes);
        }
        let chunks = self.range_chunks(address, (size as u64).max(1))?;
        let mut bytes = Vec::with_capacity(size);
        let mut remaining = size;
        for (index, offset, chunk_len) in chunks {
            if remaining == 0 {
                break;
            }
            let copy_len = chunk_len.min(remaining);
            let region = self.regions.get(index).ok_or(MemoryError::MissingRegion {
                address,
                size: (size as u64).max(1),
            })?;
            bytes.extend_from_slice(&region.data[offset..offset + copy_len]);
            remaining -= copy_len;
        }
        Ok(bytes)
    }

    /// Reads one fixed-size byte array without going through a heap allocation.
    pub fn read_fixed<const N: usize>(&self, address: u64) -> Result<[u8; N], MemoryError> {
        if let Some(backend) = self.native_backend {
            let api = unsafe { &*backend.api };
            let mut bytes = [0u8; N];
            unsafe { api.mem_read_into_raw(backend.handle, address, &mut bytes) }.map_err(
                |detail| MemoryError::NativeBackend {
                    op: "uc_mem_read",
                    detail,
                },
            )?;
            return Ok(bytes);
        }
        let mut bytes = [0u8; N];
        let chunks = self.range_chunks(address, (N as u64).max(1))?;
        let mut read = 0usize;
        for (index, offset, chunk_len) in chunks {
            if read >= N {
                break;
            }
            let copy_len = chunk_len.min(N - read);
            let region = self.regions.get(index).ok_or(MemoryError::MissingRegion {
                address,
                size: (N as u64).max(1),
            })?;
            bytes[read..read + copy_len].copy_from_slice(&region.data[offset..offset + copy_len]);
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
    }

    /// Detaches any live Unicorn backend and falls back to the local mirror only.
    pub fn detach_native(&mut self) {
        self.native_backend = None;
    }

    fn overlaps_regions(&self, base: u64, size: u64) -> bool {
        let end = base.saturating_add(size);
        let index = self.insert_index(base);
        self.regions
            .get(index)
            .map(|region| region.base < end)
            .unwrap_or(false)
            || index
                .checked_sub(1)
                .and_then(|previous| self.regions.get(previous))
                .map(|region| base < region.end())
                .unwrap_or(false)
    }

    fn overlaps_history(&self, base: u64, size: u64) -> bool {
        let end = base + size;
        self.history
            .iter()
            .any(|(other_base, other_end)| base < *other_end && *other_base < end)
    }

    fn insert_index(&self, base: u64) -> usize {
        self.regions.partition_point(|region| region.base < base)
    }

    fn region_index_for_address(&self, address: u64) -> Option<usize> {
        let index = self
            .regions
            .partition_point(|region| region.base <= address);
        index.checked_sub(1)
    }

    fn range_chunks(
        &self,
        address: u64,
        size: u64,
    ) -> Result<Vec<(usize, usize, usize)>, MemoryError> {
        let end = address
            .checked_add(size)
            .ok_or(MemoryError::MissingRegion { address, size })?;
        let mut chunks = Vec::new();
        let mut cursor = address;
        while cursor < end {
            let index = self
                .region_index_for_address(cursor)
                .ok_or(MemoryError::MissingRegion { address, size })?;
            let region = self
                .regions
                .get(index)
                .ok_or(MemoryError::MissingRegion { address, size })?;
            if cursor < region.base {
                return Err(MemoryError::MissingRegion { address, size });
            }
            let chunk_end = end.min(region.end());
            if chunk_end <= cursor {
                return Err(MemoryError::MissingRegion { address, size });
            }
            chunks.push((
                index,
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
            data: region.data[offset..offset + size].to_vec(),
        }
    }

    fn write_native(&self, address: u64, data: &[u8]) -> Result<(), MemoryError> {
        let Some(backend) = self.native_backend else {
            return Ok(());
        };
        let api = unsafe { &*backend.api };
        unsafe { api.mem_write_raw(backend.handle, address, data) }.map_err(|detail| {
            MemoryError::NativeBackend {
                op: "uc_mem_write",
                detail,
            }
        })
    }

    fn map_region_native(&self, base: u64, size: u64, perms: u32) -> Result<(), MemoryError> {
        let Some(backend) = self.native_backend else {
            return Ok(());
        };
        let api = unsafe { &*backend.api };
        unsafe { api.mem_map_raw(backend.handle, base, size, unicorn_prot(perms)) }.map_err(
            |detail| MemoryError::NativeBackend {
                op: "uc_mem_map",
                detail,
            },
        )
    }

    fn protect_region_native(&self, base: u64, size: u64, perms: u32) -> Result<(), MemoryError> {
        let Some(backend) = self.native_backend else {
            return Ok(());
        };
        let api = unsafe { &*backend.api };
        unsafe { api.mem_protect_raw(backend.handle, base, size, unicorn_prot(perms)) }.map_err(
            |detail| MemoryError::NativeBackend {
                op: "uc_mem_protect",
                detail,
            },
        )
    }

    fn unmap_region_native(&self, base: u64, size: u64) -> Result<(), MemoryError> {
        let Some(backend) = self.native_backend else {
            return Ok(());
        };
        let api = unsafe { &*backend.api };
        unsafe { api.mem_unmap_raw(backend.handle, base, size) }.map_err(|detail| {
            MemoryError::NativeBackend {
                op: "uc_mem_unmap",
                detail,
            }
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
    use super::PythonMt19937;

    #[test]
    fn python_mt19937_matches_python_getrandbits_reference() {
        let mut rng = PythonMt19937::new(0xC0DE_C0DE);
        let expected = [
            0x8AA1_15A0u64,
            0x6417_0D35,
            0xFC20_10DB,
            0x6593_1D9D,
            0x2106_2F94,
            0xB5B5_658E,
            0x7641_B930,
            0x8033_0E53,
        ];
        for value in expected {
            assert_eq!(rng.getrandbits(32), value);
        }
    }

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

        assert_eq!(memory.regions.len(), 3);
        assert_eq!(memory.regions[0].base, base);
        assert_eq!(memory.regions[0].size, 0x1000);
        assert_eq!(
            memory.regions[0].perms,
            super::PROT_READ | super::PROT_WRITE
        );
        assert_eq!(memory.regions[1].base, base + 0x1000);
        assert_eq!(memory.regions[1].size, 0x1000);
        assert_eq!(memory.regions[1].perms, super::PROT_READ);
        assert_eq!(memory.regions[2].base, base + 0x2000);
        assert_eq!(memory.regions[2].size, 0x1000);
        assert_eq!(
            memory.regions[2].perms,
            super::PROT_READ | super::PROT_WRITE
        );
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
    fn x86_reserve_window_matches_python_compatibility_span() {
        let memory = super::MemoryManager::for_tests();
        assert_eq!(memory.allocation_span(), 0x20_000_000);
    }

    #[test]
    fn x64_reserve_window_expands_beyond_legacy_512mb_span() {
        let memory = super::MemoryManager::for_arch(&crate::arch::X64_ARCH);
        assert_eq!(memory.allocation_span(), 0x1_0000_0000);
    }
}
