use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::memory::manager::{
    align_up, MemoryManager, PAGE_SIZE, PROT_EXEC, PROT_READ, PROT_WRITE,
};

const INVALID_HANDLE_VALUE: u32 = u32::MAX;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;
const FILE_MAP_COPY: u32 = 0x0001;
const FILE_MAP_WRITE: u32 = 0x0002;
const FILE_MAP_READ: u32 = 0x0004;
const FILE_MAP_ALL_ACCESS: u32 = 0x001F;
const FIRST_MAPPING_HANDLE: u32 = 0xA000_0000;

#[derive(Debug)]
pub struct MappingSource {
    pub path: String,
    pub file: std::fs::File,
    pub writable: bool,
}

#[derive(Debug)]
pub struct MappingCreateResult {
    pub handle: u32,
    pub already_exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingViewRecord {
    pub process_key: u64,
    pub base: u64,
    pub size: u64,
    pub alloc_size: u64,
    pub offset: u64,
    pub protect: u32,
    pub writable: bool,
    pub write_back: bool,
    pub copy_on_write: bool,
    pub image: bool,
    pub mapping_handle: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingWriteTarget {
    pub process_key: u64,
    pub address: u64,
    pub source_offset: usize,
    pub length: usize,
}

#[derive(Debug)]
pub struct FileMappingRecord {
    pub handle: u32,
    pub name: String,
    pub maximum_size: u64,
    pub protect: u32,
    pub writable: bool,
    pub shared_writable: bool,
    pub image: bool,
    pub path: Option<String>,
    pub open_handles: u32,
    pub views: BTreeSet<(u64, u64)>,
    content: Vec<u8>,
    source: Option<MappingSource>,
}

#[derive(Debug)]
pub struct FileMappingManager {
    next_handle: u32,
    handle_to_mapping: BTreeMap<u32, u32>,
    mappings: BTreeMap<u32, FileMappingRecord>,
    named_mappings: BTreeMap<String, u32>,
    views: BTreeMap<(u64, u64), MappingViewRecord>,
}

impl Default for FileMappingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FileMappingManager {
    /// Builds an empty file mapping manager with a dedicated handle range.
    pub fn new() -> Self {
        Self {
            next_handle: FIRST_MAPPING_HANDLE,
            handle_to_mapping: BTreeMap::new(),
            mappings: BTreeMap::new(),
            named_mappings: BTreeMap::new(),
            views: BTreeMap::new(),
        }
    }

    /// Returns one named mapping handle if present.
    pub fn find_named_mapping(&self, name: &str) -> Option<&FileMappingRecord> {
        let handle = self.named_mappings.get(&normalize_name(name))?;
        self.mappings.get(handle)
    }

    /// Opens another handle alias for one named file mapping object.
    pub fn open_named_mapping(&mut self, name: &str) -> Option<u32> {
        let mapping_handle = *self.named_mappings.get(&normalize_name(name))?;
        self.allocate_alias(mapping_handle)
    }

    /// Resolves one mapping by any live mapping handle.
    pub fn resolve_mapping(&self, handle: u32) -> Option<&FileMappingRecord> {
        let mapping_handle = self.handle_to_mapping.get(&handle)?;
        self.mappings.get(mapping_handle)
    }

    /// Creates one file mapping object or returns an alias to an existing named mapping.
    pub fn create_mapping(
        &mut self,
        file_handle: u32,
        protect: u32,
        maximum_size: u64,
        name: &str,
        image: bool,
        mut source: Option<MappingSource>,
    ) -> Option<MappingCreateResult> {
        let normalized_name = normalize_name(name);
        if let Some(&mapping_handle) = self.named_mappings.get(&normalized_name) {
            let handle = self.allocate_alias(mapping_handle)?;
            return Some(MappingCreateResult {
                handle,
                already_exists: true,
            });
        }

        let mut maximum_size = maximum_size;
        if file_handle != 0 && file_handle != INVALID_HANDLE_VALUE {
            let file_size = source
                .as_ref()
                .and_then(|source| source.file.metadata().ok())
                .map(|meta| meta.len())
                .unwrap_or(0);
            if maximum_size == 0 {
                maximum_size = file_size;
            } else {
                maximum_size = maximum_size.max(file_size);
            }
        }
        if maximum_size == 0 {
            return None;
        }

        let size = usize::try_from(maximum_size).ok()?;
        let handle = self.allocate_handle();
        let mut content = vec![0u8; size];
        if let Some(source) = source.as_mut() {
            let _ = snapshot_file_bytes(&mut source.file, &mut content);
        }

        let mapping = FileMappingRecord {
            handle,
            name: name.to_string(),
            maximum_size,
            protect,
            writable: page_protect_allows_write(protect),
            shared_writable: page_protect_allows_shared_write(protect),
            image,
            path: source.as_ref().map(|source| source.path.clone()),
            open_handles: 1,
            views: BTreeSet::new(),
            content,
            source,
        };
        self.handle_to_mapping.insert(handle, handle);
        self.mappings.insert(handle, mapping);
        if !normalized_name.is_empty() {
            self.named_mappings.insert(normalized_name, handle);
        }

        Some(MappingCreateResult {
            handle,
            already_exists: false,
        })
    }

    /// Maps one view over an existing file mapping object.
    pub fn map_view(
        &mut self,
        handle: u32,
        process_key: u64,
        desired_access: u32,
        offset: u64,
        size: u64,
        requested_base: Option<u64>,
        protect_override: Option<u32>,
        tag: &str,
        memory: &mut MemoryManager,
    ) -> Option<MappingViewRecord> {
        let mapping_handle = *self.handle_to_mapping.get(&handle)?;
        let (
            maximum_size,
            protect,
            view_writable,
            write_back,
            copy_on_write,
            image,
            payload,
            view_offset,
            view_size,
            perms,
        ) = {
            let mapping = self.mappings.get(&mapping_handle)?;
            if offset > mapping.maximum_size {
                return None;
            }
            let view_size = if size == 0 {
                mapping.maximum_size.saturating_sub(offset)
            } else {
                size
            };
            if view_size == 0 {
                return None;
            }
            let end = mapping.maximum_size.min(offset.saturating_add(view_size));
            if end <= offset {
                return None;
            }
            let actual_view_size = end - offset;
            let payload = mapping.content[offset as usize..end as usize].to_vec();
            let effective_protect = protect_override.unwrap_or(mapping.protect);
            let writable = desired_access & (FILE_MAP_WRITE | FILE_MAP_ALL_ACCESS | FILE_MAP_COPY)
                != 0
                && mapping.writable
                && page_protect_allows_write(effective_protect);
            let copy_on_write = desired_access & FILE_MAP_COPY != 0
                || page_protect_is_copy_on_write(effective_protect);
            let write_back = writable && mapping.shared_writable && !copy_on_write;
            let mut view_protect =
                effective_view_protect(effective_protect, writable, copy_on_write);
            if desired_access == FILE_MAP_READ && view_protect == PAGE_NOACCESS {
                view_protect = PAGE_READONLY;
            }
            let perms = perms_from_page_protect(view_protect);
            (
                mapping.maximum_size,
                view_protect,
                writable,
                write_back,
                copy_on_write,
                mapping.image,
                payload,
                offset,
                actual_view_size,
                perms,
            )
        };

        if view_offset > maximum_size || view_size == 0 {
            return None;
        }

        let alloc_size = align_up(view_size.max(1), PAGE_SIZE);
        let base = if let Some(requested_base) = requested_base.filter(|base| *base != 0) {
            if requested_base % PAGE_SIZE != 0 || !memory.is_free(requested_base, alloc_size, false)
            {
                return None;
            }
            memory
                .map_region(requested_base, alloc_size, perms, tag)
                .ok()?
        } else {
            memory.reserve(alloc_size, None, tag, false).ok()?
        };

        if perms
            != memory
                .find_region(base, alloc_size)
                .map(|region| region.perms)
                .unwrap_or(perms)
        {
            let _ = memory.protect(base, alloc_size, perms);
        }
        if !payload.is_empty() {
            let _ = memory.write(base, &payload);
        }
        let view = MappingViewRecord {
            process_key,
            base,
            size: view_size,
            alloc_size,
            offset: view_offset,
            protect,
            writable: view_writable,
            write_back,
            copy_on_write,
            image,
            mapping_handle,
        };
        self.views.insert((process_key, base), view.clone());
        let mapping = self.mappings.get_mut(&mapping_handle)?;
        mapping.views.insert((process_key, base));
        let _ = protect;
        Some(view)
    }

    /// Flushes one mapped view back into its mapping object and file backing.
    pub fn flush_view(
        &mut self,
        process_key: u64,
        base: u64,
        size: u64,
        memory: &mut MemoryManager,
    ) -> bool {
        let Some(view) = self.views.get(&(process_key, base)).cloned() else {
            return false;
        };
        let length = if size == 0 {
            view.size
        } else {
            view.size.min(size)
        };
        self.flush_view_range(&view, length, memory)
    }

    /// Unmaps one previously mapped view.
    pub fn unmap_view(&mut self, process_key: u64, base: u64, memory: &mut MemoryManager) -> bool {
        let Some(view) = self.views.remove(&(process_key, base)) else {
            return false;
        };
        let _ = self.flush_view_range(&view, view.size, memory);
        let _ = memory.unmap(view.base, view.alloc_size);
        if let Some(mapping) = self.mappings.get_mut(&view.mapping_handle) {
            mapping.views.remove(&(process_key, base));
        }
        self.maybe_destroy_mapping(view.mapping_handle);
        true
    }

    /// Closes one mapping-object handle alias.
    pub fn close_handle(&mut self, handle: u32) -> bool {
        let Some(mapping_handle) = self.handle_to_mapping.remove(&handle) else {
            return false;
        };
        if let Some(mapping) = self.mappings.get_mut(&mapping_handle) {
            mapping.open_handles = mapping.open_handles.saturating_sub(1);
        }
        self.maybe_destroy_mapping(mapping_handle);
        true
    }

    /// Returns the mapped backing path for one virtual address if it belongs to a mapped view.
    pub fn mapped_path_for_address(&self, process_key: u64, address: u64) -> Option<&str> {
        let view = self.view_containing(process_key, address)?;
        self.mappings.get(&view.mapping_handle)?.path.as_deref()
    }

    /// Returns whether the address is inside one live mapped view.
    pub fn contains_address(&self, process_key: u64, address: u64) -> bool {
        self.view_containing(process_key, address).is_some()
    }

    /// Returns whether the mapped view covering one address behaves like an image section.
    pub fn view_is_image(&self, process_key: u64, address: u64) -> Option<bool> {
        Some(self.view_containing(process_key, address)?.image)
    }

    /// Records one in-memory write and returns sibling targets that should observe the same bytes.
    pub fn record_view_write(
        &mut self,
        process_key: u64,
        address: u64,
        data: &[u8],
    ) -> Option<Vec<MappingWriteTarget>> {
        if data.is_empty() {
            return Some(Vec::new());
        }
        let view = self.view_containing(process_key, address)?.clone();
        let write_start = address.checked_sub(view.base)?;
        let write_end = write_start.checked_add(data.len() as u64)?;
        if write_end > view.size {
            return None;
        }
        if view.copy_on_write {
            return Some(Vec::new());
        }

        let mapping_start = view.offset.checked_add(write_start)?;
        let mapping_end = mapping_start.checked_add(data.len() as u64)?;
        let mapping = self.mappings.get_mut(&view.mapping_handle)?;
        if mapping_end as usize > mapping.content.len() {
            return None;
        }
        mapping.content[mapping_start as usize..mapping_end as usize].copy_from_slice(data);

        Some(
            mapping
                .views
                .iter()
                .filter_map(|&(target_process_key, target_base)| {
                    if target_process_key == process_key && target_base == view.base {
                        return None;
                    }
                    let target_view = self.views.get(&(target_process_key, target_base))?;
                    if target_view.copy_on_write {
                        return None;
                    }
                    let target_start = target_view.offset;
                    let target_end = target_view.offset.checked_add(target_view.size)?;
                    let overlap_start = mapping_start.max(target_start);
                    let overlap_end = mapping_end.min(target_end);
                    if overlap_start >= overlap_end {
                        return None;
                    }
                    Some(MappingWriteTarget {
                        process_key: target_process_key,
                        address: target_view.base + (overlap_start - target_start),
                        source_offset: (overlap_start - mapping_start) as usize,
                        length: (overlap_end - overlap_start) as usize,
                    })
                })
                .collect(),
        )
    }

    fn allocate_alias(&mut self, mapping_handle: u32) -> Option<u32> {
        let handle = self.allocate_handle();
        let mapping = self.mappings.get_mut(&mapping_handle)?;
        mapping.open_handles = mapping.open_handles.saturating_add(1);
        self.handle_to_mapping.insert(handle, mapping_handle);
        Some(handle)
    }

    fn allocate_handle(&mut self) -> u32 {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(4);
        handle
    }

    fn flush_view_range(
        &mut self,
        view: &MappingViewRecord,
        length: u64,
        memory: &mut MemoryManager,
    ) -> bool {
        if length == 0 || !view.write_back {
            return true;
        }
        let Ok(bytes) = memory.read(view.base, length as usize) else {
            return false;
        };
        let Some(mapping) = self.mappings.get_mut(&view.mapping_handle) else {
            return false;
        };
        let start = view.offset as usize;
        let end = start.saturating_add(bytes.len()).min(mapping.content.len());
        if end <= start {
            return true;
        }
        mapping.content[start..end].copy_from_slice(&bytes[..end - start]);
        write_back_range(mapping, start, end - start);
        true
    }

    fn maybe_destroy_mapping(&mut self, mapping_handle: u32) {
        let should_destroy = self
            .mappings
            .get(&mapping_handle)
            .map(|mapping| mapping.open_handles == 0 && mapping.views.is_empty())
            .unwrap_or(false);
        if !should_destroy {
            return;
        }
        let Some(mapping) = self.mappings.remove(&mapping_handle) else {
            return;
        };
        let normalized_name = normalize_name(&mapping.name);
        if !normalized_name.is_empty()
            && self.named_mappings.get(&normalized_name) == Some(&mapping_handle)
        {
            self.named_mappings.remove(&normalized_name);
        }
    }

    fn view_containing(&self, process_key: u64, address: u64) -> Option<&MappingViewRecord> {
        self.views.values().find(|view| {
            view.process_key == process_key
                && view.base <= address
                && address < view.base + view.alloc_size
        })
    }
}

fn normalize_name(name: &str) -> String {
    let normalized = name.trim().replace('/', "\\").to_ascii_lowercase();
    normalized
        .strip_prefix("\\basenamedobjects\\")
        .or_else(|| normalized.strip_prefix("basenamedobjects\\"))
        .unwrap_or(&normalized)
        .to_string()
}

fn snapshot_file_bytes(file: &mut std::fs::File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let position = file.stream_position()?;
    file.seek(SeekFrom::Start(0))?;
    let read = file.read(buffer)?;
    file.seek(SeekFrom::Start(position))?;
    Ok(read)
}

fn write_back_range(mapping: &mut FileMappingRecord, start: usize, length: usize) {
    let Some(source) = mapping.source.as_mut() else {
        return;
    };
    if !source.writable || length == 0 {
        return;
    }
    let Ok(position) = source.file.stream_position() else {
        return;
    };
    if source.file.seek(SeekFrom::Start(start as u64)).is_err() {
        return;
    }
    if source
        .file
        .write_all(&mapping.content[start..start + length])
        .is_err()
    {
        let _ = source.file.seek(SeekFrom::Start(position));
        return;
    }
    let _ = source.file.flush();
    let _ = source.file.seek(SeekFrom::Start(position));
}

fn perms_from_page_protect(protect: u32) -> u32 {
    match base_page_protect(protect) {
        PAGE_EXECUTE_WRITECOPY => PROT_READ | PROT_WRITE | PROT_EXEC,
        PAGE_EXECUTE_READWRITE => PROT_READ | PROT_WRITE | PROT_EXEC,
        PAGE_EXECUTE_READ => PROT_READ | PROT_EXEC,
        PAGE_EXECUTE => PROT_EXEC,
        PAGE_WRITECOPY => PROT_READ | PROT_WRITE,
        PAGE_READWRITE => PROT_READ | PROT_WRITE,
        PAGE_READONLY => PROT_READ,
        PAGE_NOACCESS => 0,
        _ => PROT_READ | PROT_WRITE,
    }
}

fn page_protect_allows_write(protect: u32) -> bool {
    matches!(
        base_page_protect(protect),
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

fn page_protect_allows_shared_write(protect: u32) -> bool {
    matches!(
        base_page_protect(protect),
        PAGE_READWRITE | PAGE_EXECUTE_READWRITE
    )
}

fn page_protect_is_copy_on_write(protect: u32) -> bool {
    matches!(
        base_page_protect(protect),
        PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY
    )
}

fn effective_view_protect(protect: u32, writable: bool, copy_on_write: bool) -> u32 {
    let modifiers = protect & !0xFF;
    let mut effective = match base_page_protect(protect) {
        PAGE_READWRITE | PAGE_WRITECOPY if !writable => PAGE_READONLY,
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY if !writable => PAGE_EXECUTE_READ,
        _ => protect,
    };

    if copy_on_write && writable {
        effective = match effective {
            PAGE_READWRITE | PAGE_READONLY | PAGE_WRITECOPY => PAGE_WRITECOPY,
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY => {
                PAGE_EXECUTE_WRITECOPY
            }
            _ => effective,
        };
    }

    base_page_protect(effective) | modifiers
}

fn base_page_protect(protect: u32) -> u32 {
    protect & !PAGE_GUARD
}
