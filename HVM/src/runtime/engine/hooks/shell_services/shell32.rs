use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_shell32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("shell32.dll", "IsUserAnAdmin") => true,
            ("shell32.dll", "ShellExecuteW") => true,
            ("shell32.dll", "ShellExecuteExW") => true,
            ("shell32.dll", "SHBrowseForFolderA") => true,
            ("shell32.dll", "SHGetFolderPathW") => true,
            ("shell32.dll", "SHGetMalloc") => true,
            ("shell32.dll", "IMalloc_QueryInterface") => true,
            ("shell32.dll", "IMalloc_AddRef") => true,
            ("shell32.dll", "IMalloc_Release") => true,
            ("shell32.dll", "IMalloc_Alloc") => true,
            ("shell32.dll", "IMalloc_Realloc") => true,
            ("shell32.dll", "IMalloc_Free") => true,
            ("shell32.dll", "IMalloc_GetSize") => true,
            ("shell32.dll", "IMalloc_DidAlloc") => true,
            ("shell32.dll", "IMalloc_HeapMinimize") => true,
            ("shell32.dll", "SHGetPathFromIDListW") => true,
            ("shell32.dll", "SHGetSpecialFolderLocation") => true,
            ("shell32.dll", "SHGetImageList") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("shell32.dll", "IsUserAnAdmin") => {
                    let active_user = self.active_user_name().trim();
                    let is_admin = self
                        .environment_profile
                        .users
                        .iter()
                        .find(|user| user.name.eq_ignore_ascii_case(active_user))
                        .map(|user| user.privilege_level >= 2)
                        .unwrap_or_else(|| {
                            active_user.eq_ignore_ascii_case("Administrator")
                                || active_user.eq_ignore_ascii_case("Admin")
                        });
                    Ok(is_admin as u64)
                }
                ("shell32.dll", "ShellExecuteW") => {
                    let image = self.read_wide_string_from_memory(arg(args, 2))?;
                    let parameters = self.read_wide_string_from_memory(arg(args, 3))?;
                    let directory = self.read_wide_string_from_memory(arg(args, 4))?;
                    let effective_directory = if directory.is_empty() {
                        self.current_directory_display_text()
                    } else {
                        self.resolve_runtime_display_path(&directory)
                    };
                    let launched = self.processes.spawn_shell_execute(
                        &image,
                        non_empty(&parameters),
                        Some(&effective_directory),
                    );
                    if let Some(handle) = launched {
                        let command_line = if parameters.is_empty() {
                            image.clone()
                        } else {
                            format!("{image} {parameters}")
                        };
                        self.log_process_spawn(
                            "ShellExecuteW",
                            handle,
                            &image,
                            &command_line,
                            &effective_directory,
                        )?;
                    }
                    Ok(if launched.is_some() {
                        SHELL_EXECUTE_SUCCESS as u64
                    } else {
                        0
                    })
                }
                ("shell32.dll", "ShellExecuteExW") => {
                    let info = arg(args, 0);
                    if info == 0 {
                        return Ok(0);
                    }
                    let fmask = self.read_u32(info + 0x04)?;
                    let image =
                        self.read_wide_string_from_memory(self.read_u32(info + 0x10)? as u64)?;
                    let parameters =
                        self.read_wide_string_from_memory(self.read_u32(info + 0x14)? as u64)?;
                    let directory =
                        self.read_wide_string_from_memory(self.read_u32(info + 0x18)? as u64)?;
                    let effective_directory = if directory.is_empty() {
                        self.current_directory_display_text()
                    } else {
                        self.resolve_runtime_display_path(&directory)
                    };
                    let handle = self.processes.spawn_shell_execute(
                        &image,
                        non_empty(&parameters),
                        Some(&effective_directory),
                    );
                    if let Some(process_handle) = handle {
                        let command_line = if parameters.is_empty() {
                            image.clone()
                        } else {
                            format!("{image} {parameters}")
                        };
                        self.log_process_spawn(
                            "ShellExecuteExW",
                            process_handle,
                            &image,
                            &command_line,
                            &effective_directory,
                        )?;
                    }
                    if fmask & SEE_MASK_NOCLOSEPROCESS != 0 {
                        self.write_u32(info + 0x38, handle.unwrap_or(0))?;
                    }
                    Ok(if handle.is_some() { 1 } else { 0 })
                }
                ("shell32.dll", "SHBrowseForFolderA") => Ok(0),
                ("shell32.dll", "SHGetFolderPathW") => {
                    let path = self.shell_folder_path_from_csidl(arg(args, 1) as u32);
                    let _ = self.write_wide_string_to_memory(arg(args, 4), 260, &path)?;
                    Ok(ERROR_SUCCESS)
                }
                ("shell32.dll", "SHGetMalloc") => {
                    if arg(args, 0) != 0 {
                        let allocator = self.ensure_shell_imalloc()?;
                        self.write_u32(arg(args, 0), allocator as u32)?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                ("shell32.dll", "IMalloc_QueryInterface") => {
                    if arg(args, 2) != 0 {
                        self.write_u32(arg(args, 2), arg(args, 0) as u32)?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                ("shell32.dll", "IMalloc_AddRef") => Ok(2),
                ("shell32.dll", "IMalloc_Release") => Ok(1),
                ("shell32.dll", "IMalloc_Alloc") => {
                    if arg(args, 1) == 0 {
                        Ok(0)
                    } else {
                        self.alloc_process_heap_block(arg(args, 1), "IMalloc::Alloc")
                    }
                }
                ("shell32.dll", "IMalloc_Realloc") => {
                    let old_address = arg(args, 1);
                    let new_size = arg(args, 2);
                    if old_address == 0 {
                        return self.alloc_process_heap_block(new_size.max(1), "IMalloc::Realloc");
                    }
                    if new_size == 0 {
                        let _ = self.heaps.free(self.heaps.process_heap(), old_address);
                        return Ok(0);
                    }
                    let old_size = self.heaps.size(self.heaps.process_heap(), old_address);
                    if old_size == u32::MAX as u64 {
                        return Ok(0);
                    }
                    let new_address =
                        self.alloc_process_heap_block(new_size.max(1), "IMalloc::Realloc")?;
                    let bytes =
                        self.read_bytes_from_memory(old_address, old_size.min(new_size) as usize)?;
                    self.modules.memory_mut().write(new_address, &bytes)?;
                    let _ = self.heaps.free(self.heaps.process_heap(), old_address);
                    Ok(new_address)
                }
                ("shell32.dll", "IMalloc_Free") => {
                    let _ = self.heaps.free(self.heaps.process_heap(), arg(args, 1));
                    Ok(0)
                }
                ("shell32.dll", "IMalloc_GetSize") => {
                    let size = self.heaps.size(self.heaps.process_heap(), arg(args, 1));
                    Ok(if size == u32::MAX as u64 { 0 } else { size })
                }
                ("shell32.dll", "IMalloc_DidAlloc") => Ok((self
                    .heaps
                    .size(self.heaps.process_heap(), arg(args, 1))
                    != u32::MAX as u64)
                    as u64),
                ("shell32.dll", "IMalloc_HeapMinimize") => Ok(0),
                ("shell32.dll", "SHGetPathFromIDListW") => {
                    if arg(args, 0) == 0 || arg(args, 1) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(0)
                    } else {
                        let path = self.read_wide_string_from_memory(arg(args, 0))?;
                        let _ = self.write_wide_string_to_memory(arg(args, 1), 260, &path)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                ("shell32.dll", "SHGetSpecialFolderLocation") => {
                    if arg(args, 2) == 0 {
                        Ok(E_INVALIDARG_HRESULT)
                    } else {
                        let path = self.shell_folder_path_from_csidl(arg(args, 1) as u32);
                        let mut bytes = path
                            .encode_utf16()
                            .flat_map(u16::to_le_bytes)
                            .collect::<Vec<_>>();
                        bytes.extend_from_slice(&[0, 0]);
                        let pidl = self.alloc_process_heap_block(
                            bytes.len() as u64,
                            "SHGetSpecialFolderLocation",
                        )?;
                        self.modules.memory_mut().write(pidl, &bytes)?;
                        self.write_pointer_value(arg(args, 2), pidl)?;
                        Ok(ERROR_SUCCESS)
                    }
                }
                ("shell32.dll", "SHGetImageList") => {
                    if arg(args, 2) != 0 {
                        if self.arch.is_x86() {
                            self.write_u32(arg(args, 2), 0)?;
                        } else {
                            self.modules
                                .memory_mut()
                                .write(arg(args, 2), &0u64.to_le_bytes())?;
                        }
                    }
                    Ok(0)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
