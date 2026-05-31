use std::path::PathBuf;

use goblin::pe::relocation::{
    IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
};
use goblin::pe::PE;

use crate::error::VmError;
use crate::memory::manager::MemoryManager;

/// Applies base relocations when the image cannot be mapped at its preferred base.
pub fn apply_base_relocations(
    pe: &PE<'_>,
    mapped_base: u64,
    memory: &mut MemoryManager,
) -> Result<(), VmError> {
    if mapped_base == pe.image_base {
        return Ok(());
    }
    let delta = mapped_base as i128 - pe.image_base as i128;
    apply_delta_relocations(pe, mapped_base, delta, memory)
}

/// Applies an arbitrary address delta to every relocation entry in the PE image
/// currently loaded at `image_base`.
///
/// Unlike [`apply_base_relocations`] which computes delta from `pe.image_base`,
/// this function accepts an explicit `delta`.  This is used to re-relocate a
/// visible alias copy of a module so that all absolute addresses inside the
/// alias point to the visible address space instead of the mapped address space.
pub fn apply_delta_relocations(
    pe: &PE<'_>,
    image_base: u64,
    delta: i128,
    memory: &mut MemoryManager,
) -> Result<(), VmError> {
    if delta == 0 {
        return Ok(());
    }
    let Some(relocation_data) = pe.relocation_data.as_ref() else {
        return Ok(());
    };

    for block in relocation_data.blocks() {
        let block = block.map_err(|source| VmError::ParsePe {
            path: PathBuf::from("<relocations>"),
            source,
        })?;
        for word in block.words() {
            let word = word.map_err(|source| VmError::ParsePe {
                path: PathBuf::from("<relocations>"),
                source,
            })?;
            let address = image_base + block.rva as u64 + word.offset() as u64;
            match word.reloc_type() as u16 {
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_HIGHLOW => {
                    let raw = memory.read(address, 4)?;
                    let original = u32::from_le_bytes(raw.try_into().unwrap()) as i128;
                    let updated = original + delta;
                    memory.write(address, &(updated as u32).to_le_bytes())?;
                }
                IMAGE_REL_BASED_DIR64 => {
                    let raw = memory.read(address, 8)?;
                    let original = u64::from_le_bytes(raw.try_into().unwrap()) as i128;
                    let updated = original + delta;
                    memory.write(address, &(updated as u64).to_le_bytes())?;
                }
                _ => {}
            }
        }
    }

    Ok(())
}
