use super::*;

pub(super) fn arg(args: &[u64], index: usize) -> u64 {
    args.get(index).copied().unwrap_or(0)
}

pub(super) fn non_empty(value: &str) -> Option<&str> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

pub(super) fn is_std_handle(handle: u64) -> bool {
    matches!(
        handle & 0xFFFF_FFFF,
        STD_INPUT_HANDLE | STD_OUTPUT_HANDLE | STD_ERROR_HANDLE
    )
}

pub(super) fn compare_ci(left: &str, right: &str) -> i32 {
    use std::cmp::Ordering;

    match left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase()) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

pub(super) fn seek_file(
    file: &mut std::fs::File,
    offset: u64,
    method: u64,
) -> Result<u64, VmError> {
    let from = match method {
        1 => SeekFrom::Current(offset as i64),
        2 => SeekFrom::End(offset as i64),
        _ => SeekFrom::Start(offset),
    };
    file.seek(from).map_err(|source| VmError::CommandIo {
        program: "file seek".to_string(),
        source,
    })
}

pub(super) fn unicorn_prot(perms: u32) -> u32 {
    let mut mapped = 0;
    if perms & crate::memory::manager::PROT_READ != 0 {
        mapped |= UC_PROT_READ;
    }
    if perms & crate::memory::manager::PROT_WRITE != 0 {
        mapped |= UC_PROT_WRITE;
    }
    if perms & crate::memory::manager::PROT_EXEC != 0 {
        mapped |= UC_PROT_EXEC;
    }
    mapped
}

pub(super) fn detect_runtime_architecture(
    path: &std::path::Path,
) -> Result<&'static ArchSpec, VmError> {
    let bytes = fs::read(path).map_err(|source| VmError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let pe = PE::parse(&bytes).map_err(|source| VmError::ParsePe {
        path: path.to_path_buf(),
        source,
    })?;
    arch_spec(pe.header.coff_header.machine)
        .ok_or(VmError::UnsupportedMachine(pe.header.coff_header.machine))
}

impl VirtualExecutionEngine {
    pub(super) fn sign_extend_win32_handle_for_arch(&self, value: u64) -> u64 {
        let lower = value & 0xFFFF_FFFF;
        if self.arch.is_x86() || lower & 0x8000_0000 == 0 {
            lower
        } else {
            lower | 0xFFFF_FFFF_0000_0000
        }
    }

    pub(super) fn invalid_handle_value_for_arch(&self) -> u64 {
        self.sign_extend_win32_handle_for_arch(INVALID_HANDLE_VALUE)
    }

    pub(super) fn current_process_pseudo_handle(&self) -> u64 {
        self.sign_extend_win32_handle_for_arch(PROCESS_HANDLE_PSEUDO)
    }

    pub(super) fn std_handle_value_for_arch(&self, value: u64) -> u64 {
        self.sign_extend_win32_handle_for_arch(value)
    }

    pub(super) fn is_invalid_handle_value(&self, value: u64) -> bool {
        (value & 0xFFFF_FFFF) == INVALID_HANDLE_VALUE
    }
}
