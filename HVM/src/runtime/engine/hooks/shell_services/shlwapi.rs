use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_shlwapi_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("shlwapi.dll", "SHGetValueA") => true,
            ("shlwapi.dll", "SHGetValueW") => true,
            ("shlwapi.dll", "SHSetValueA") => true,
            ("shlwapi.dll", "SHSetValueW") => true,
            ("shlwapi.dll", "PathAddBackslashW") => true,
            ("shlwapi.dll", "PathAppendW") => true,
            ("shlwapi.dll", "PathCombineW") => true,
            ("shlwapi.dll", "PathFileExistsW") => true,
            ("shlwapi.dll", "PathFindExtensionW") => true,
            ("shlwapi.dll", "PathFindFileNameW") => true,
            ("shlwapi.dll", "PathRemoveFileSpecW") => true,
            ("shlwapi.dll", "StrCmpIW") => true,
            ("shlwapi.dll", "StrCmpNIW") => true,
            ("shlwapi.dll", "StrTrimA") => true,
            ("shlwapi.dll", "StrRChrW") => true,
            ("shlwapi.dll", "StrStrIA") => true,
            ("shlwapi.dll", "StrStrIW") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("shlwapi.dll", "SHGetValueA") => self.sh_get_value(
                    arg(args, 0) as u32,
                    self.read_c_string_from_memory(arg(args, 1))?,
                    self.read_c_string_from_memory(arg(args, 2))?,
                    arg(args, 3),
                    arg(args, 4),
                    arg(args, 5),
                ),
                ("shlwapi.dll", "SHGetValueW") => self.sh_get_value(
                    arg(args, 0) as u32,
                    self.read_wide_string_from_memory(arg(args, 1))?,
                    self.read_wide_string_from_memory(arg(args, 2))?,
                    arg(args, 3),
                    arg(args, 4),
                    arg(args, 5),
                ),
                ("shlwapi.dll", "SHSetValueA") => self.sh_set_value(
                    arg(args, 0) as u32,
                    self.read_c_string_from_memory(arg(args, 1))?,
                    self.read_c_string_from_memory(arg(args, 2))?,
                    arg(args, 3) as u32,
                    arg(args, 4),
                    arg(args, 5),
                ),
                ("shlwapi.dll", "SHSetValueW") => self.sh_set_value(
                    arg(args, 0) as u32,
                    self.read_wide_string_from_memory(arg(args, 1))?,
                    self.read_wide_string_from_memory(arg(args, 2))?,
                    arg(args, 3) as u32,
                    arg(args, 4),
                    arg(args, 5),
                ),
                ("shlwapi.dll", "PathAddBackslashW") => {
                    let buffer = arg(args, 0);
                    let mut path = self.read_wide_string_from_memory(buffer)?;
                    if !path.ends_with('\\') && !path.ends_with('/') {
                        path.push('\\');
                    }
                    let _ = self.write_wide_string_to_memory(buffer, 0x208, &path)?;
                    Ok(buffer)
                }
                ("shlwapi.dll", "PathAppendW") => {
                    let buffer = arg(args, 0);
                    let more = self.read_wide_string_from_memory(arg(args, 1))?;
                    let mut path = self.read_wide_string_from_memory(buffer)?;
                    if !path.is_empty() && !path.ends_with('\\') && !path.ends_with('/') {
                        path.push('\\');
                    }
                    path.push_str(&more);
                    let _ = self.write_wide_string_to_memory(buffer, 0x208, &path)?;
                    Ok(1)
                }
                ("shlwapi.dll", "PathCombineW") => {
                    let base = self.read_wide_string_from_memory(arg(args, 1))?;
                    let more = self.read_wide_string_from_memory(arg(args, 2))?;
                    let joined = if base.is_empty() {
                        more
                    } else if more.is_empty() {
                        base
                    } else {
                        format!("{}\\{}", base.trim_end_matches(['\\', '/']), more)
                    };
                    let _ = self.write_wide_string_to_memory(arg(args, 0), 0x208, &joined)?;
                    Ok(arg(args, 0))
                }
                ("shlwapi.dll", "PathFileExistsW") => {
                    let path = self.read_wide_string_from_memory(arg(args, 0))?;
                    if path.is_empty() {
                        return Ok(0);
                    }
                    let Some(target) =
                        self.prepare_runtime_read_target(&path, "PathFileExistsW")?
                    else {
                        return Ok(0);
                    };
                    Ok(target.exists() as u64)
                }
                ("shlwapi.dll", "PathFindExtensionW") => {
                    let buffer = arg(args, 0);
                    let path = self.read_wide_string_from_memory(buffer)?;
                    let file_name = path.rsplit(['\\', '/']).next().unwrap_or(&path);
                    if let Some(index) = file_name.rfind('.') {
                        let prefix_len = path.len().saturating_sub(file_name.len());
                        let offset = path[..prefix_len + index].encode_utf16().count() as u64 * 2;
                        Ok(buffer + offset)
                    } else {
                        let offset = path.encode_utf16().count() as u64 * 2;
                        Ok(buffer + offset)
                    }
                }
                ("shlwapi.dll", "PathFindFileNameW") => self.path_find_file_name_w(arg(args, 0)),
                ("shlwapi.dll", "PathRemoveFileSpecW") => {
                    let buffer = arg(args, 0);
                    let mut path =
                        std::path::PathBuf::from(self.read_wide_string_from_memory(buffer)?);
                    let result = path.pop();
                    let _ =
                        self.write_wide_string_to_memory(buffer, 0x208, &path.to_string_lossy())?;
                    Ok(result as u64)
                }
                ("shlwapi.dll", "StrCmpIW") => {
                    let left = self.read_wide_string_from_memory(arg(args, 0))?;
                    let right = self.read_wide_string_from_memory(arg(args, 1))?;
                    Ok(compare_ci(&left, &right) as u32 as u64)
                }
                ("shlwapi.dll", "StrCmpNIW") => {
                    let count = arg(args, 2) as usize;
                    let left = self.read_wide_string_from_memory(arg(args, 0))?;
                    let right = self.read_wide_string_from_memory(arg(args, 1))?;
                    Ok(compare_ci(
                        &left.chars().take(count).collect::<String>(),
                        &right.chars().take(count).collect::<String>(),
                    ) as u32 as u64)
                }
                ("shlwapi.dll", "StrTrimA") => {
                    let buffer = arg(args, 0);
                    let text = self.read_c_string_from_memory(buffer)?;
                    let trim_chars = self.read_c_string_from_memory(arg(args, 1))?;
                    let trimmed = text.trim_matches(|ch| trim_chars.contains(ch)).to_string();
                    let _ = self.write_c_string_to_memory(buffer, 0x1000, &trimmed)?;
                    Ok(1)
                }
                ("shlwapi.dll", "StrRChrW") => {
                    let haystack = self.read_wide_string_from_memory(arg(args, 0))?;
                    let target = char::from_u32(arg(args, 2) as u32).unwrap_or('\0');
                    if let Some(index) = haystack.rfind(target) {
                        let offset = haystack[..index].encode_utf16().count() as u64 * 2;
                        Ok(arg(args, 0) + offset)
                    } else {
                        Ok(0)
                    }
                }
                ("shlwapi.dll", "StrStrIA") => {
                    let haystack = self.read_c_string_from_memory(arg(args, 0))?;
                    let needle = self.read_c_string_from_memory(arg(args, 1))?;
                    if let Some(index) = haystack
                        .to_ascii_lowercase()
                        .find(&needle.to_ascii_lowercase())
                    {
                        Ok(arg(args, 0) + index as u64)
                    } else {
                        Ok(0)
                    }
                }
                ("shlwapi.dll", "StrStrIW") => {
                    let haystack = self.read_wide_string_from_memory(arg(args, 0))?;
                    let needle = self.read_wide_string_from_memory(arg(args, 1))?;
                    if let Some(index) = haystack
                        .to_ascii_lowercase()
                        .find(&needle.to_ascii_lowercase())
                    {
                        let offset = haystack[..index].encode_utf16().count() as u64 * 2;
                        Ok(arg(args, 0) + offset)
                    } else {
                        Ok(0)
                    }
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
