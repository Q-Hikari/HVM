use super::*;
use crate::runtime::windows_env::ldr_region_size_for_arch;

impl VirtualExecutionEngine {
    pub(super) fn resolve_entry_address(
        &mut self,
        entry_module: &ModuleRecord,
    ) -> Result<u64, VmError> {
        let address = if let Some(export) = self.core.config.entry_export.as_deref() {
            self.core.modules.resolve_export(
                entry_module.base,
                &self.core.config,
                &mut self.core.hooks,
                Some(export),
                None,
            )
        } else if let Some(ordinal) = self.core.config.entry_ordinal {
            self.core.modules.resolve_export(
                entry_module.base,
                &self.core.config,
                &mut self.core.hooks,
                None,
                Some(ordinal),
            )
        } else {
            entry_module.entrypoint
        };
        if address != 0 {
            return Ok(address);
        }

        let detail = if let Some(export) = self.core.config.entry_export.as_deref() {
            format!(
                "failed to resolve export `{export}` from {}",
                entry_module.name
            )
        } else if let Some(ordinal) = self.core.config.entry_ordinal {
            format!(
                "failed to resolve ordinal #{ordinal} from {}",
                entry_module.name
            )
        } else {
            format!(
                "module {} does not expose a non-zero entrypoint",
                entry_module.name
            )
        };
        Err(VmError::NativeExecution { op: "load", detail })
    }

    pub(super) fn prepare_entry_arguments(
        &mut self,
        entry_module: &ModuleRecord,
    ) -> Result<Vec<u64>, VmError> {
        if self.core.config.entry_args.is_empty()
            && self.core.entry_invocation == EntryInvocation::NativeEntrypoint
            && Self::module_looks_like_dll(entry_module)
        {
            return Ok(vec![entry_module.base, DLL_PROCESS_ATTACH, 0]);
        }

        let arguments = self.core.config.entry_args.clone();
        arguments
            .iter()
            .enumerate()
            .map(|(index, argument)| self.prepare_entry_argument(index, argument))
            .collect()
    }

    pub(super) fn prepare_entry_argument(
        &mut self,
        index: usize,
        argument: &EntryArgument,
    ) -> Result<u64, VmError> {
        match argument {
            EntryArgument::Value(value) => Ok(*value),
            EntryArgument::Null => Ok(0),
            EntryArgument::AnsiString(text) => {
                let mut bytes = text.as_bytes().to_vec();
                bytes.push(0);
                self.allocate_entry_argument_buffer(index, &bytes)
            }
            EntryArgument::WideString(text) => {
                let bytes = text
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .chain([0, 0])
                    .collect::<Vec<_>>();
                self.allocate_entry_argument_buffer(index, &bytes)
            }
            EntryArgument::Bytes(bytes) => self.allocate_entry_argument_buffer(index, bytes),
        }
    }

    pub(super) fn allocate_entry_argument_buffer(
        &mut self,
        index: usize,
        contents: &[u8],
    ) -> Result<u64, VmError> {
        let size = contents.len().max(1) as u64;
        let address = self.core.modules.memory_mut().reserve(
            size,
            None,
            &format!("entry_arg:{index}"),
            true,
        )?;
        if contents.is_empty() {
            self.core.modules.memory_mut().write(address, &[0])?;
        } else {
            self.core.modules.memory_mut().write(address, contents)?;
        }
        Ok(address)
    }

    pub(super) fn module_looks_like_dll(module: &ModuleRecord) -> bool {
        module.is_dll
            || module
                .path
                .as_ref()
                .and_then(|path| path.extension())
                .map(|extension| extension.to_string_lossy().eq_ignore_ascii_case("dll"))
                .unwrap_or_else(|| module.name.ends_with(".dll"))
    }

    pub(super) fn ensure_supported_execution_architecture(
        &self,
        module: &ModuleRecord,
        operation: &'static str,
    ) -> Result<(), VmError> {
        if module.synthetic || module.arch.eq_ignore_ascii_case(self.core.arch.name) {
            return Ok(());
        }
        Err(VmError::UnsupportedExecutionArchitecture {
            operation,
            path: module
                .path
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from(&module.name)),
            arch: module.arch.clone(),
        })
    }

    pub(super) fn reserve_process_env_footprint(&mut self) -> Result<(), VmError> {
        // Reserve process environment memory before module initializers run.
        for (size, tag) in [
            (0x2000, "teb"),
            (0x3000, "peb"),
            (ldr_region_size_for_arch(self.core.arch), "ldr"),
            (0x2000, "params"),
            (0x1000, "tls_bitmap"),
            (0x1000, "tls_bitmap_bits"),
            (0x1000, "process_heaps"),
            (0x1000, "params_image"),
            (0x1000, "params_command"),
            (0x1000, "params_command_a"),
            (0x1000, "params_current_directory"),
            (0x1000, "params_dll_path"),
            (0x4000, "params_environment_w"),
            (0x2000, "params_environment_a"),
            (0x1000, "gdt"),
        ] {
            self.core
                .modules
                .memory_mut()
                .reserve(size, None, tag, true)?;
        }
        Ok(())
    }
}
