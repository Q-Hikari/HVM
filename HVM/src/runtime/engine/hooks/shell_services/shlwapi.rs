use sha2::{Digest, Sha256};

use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_shlwapi_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
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
            ("shlwapi.dll", "HashData") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("shlwapi.dll", "SHGetValueA") => self.sh_get_value(
                    ctx.raw(0) as u32,
                    self.read_c_string_from_memory(ctx.raw(1))?,
                    self.read_c_string_from_memory(ctx.raw(2))?,
                    false,
                    ctx.raw(3),
                    ctx.raw(4),
                    ctx.raw(5),
                ),
                ("shlwapi.dll", "SHGetValueW") => self.sh_get_value(
                    ctx.raw(0) as u32,
                    self.read_wide_string_from_memory(ctx.raw(1))?,
                    self.read_wide_string_from_memory(ctx.raw(2))?,
                    true,
                    ctx.raw(3),
                    ctx.raw(4),
                    ctx.raw(5),
                ),
                ("shlwapi.dll", "SHSetValueA") => self.sh_set_value(
                    ctx.raw(0) as u32,
                    self.read_c_string_from_memory(ctx.raw(1))?,
                    self.read_c_string_from_memory(ctx.raw(2))?,
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5),
                ),
                ("shlwapi.dll", "SHSetValueW") => self.sh_set_value(
                    ctx.raw(0) as u32,
                    self.read_wide_string_from_memory(ctx.raw(1))?,
                    self.read_wide_string_from_memory(ctx.raw(2))?,
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5),
                ),
                ("shlwapi.dll", "PathAddBackslashW") => {
                    let buffer = ctx.raw(0);
                    let mut path = self.read_wide_string_from_memory(buffer)?;
                    if !path.ends_with('\\') && !path.ends_with('/') {
                        path.push('\\');
                    }
                    let _ = self.write_wide_string_to_memory(buffer, 0x208, &path)?;
                    Ok(buffer)
                }
                ("shlwapi.dll", "PathAppendW") => {
                    let buffer = ctx.raw(0);
                    let more = self.read_wide_string_from_memory(ctx.raw(1))?;
                    let mut path = self.read_wide_string_from_memory(buffer)?;
                    if !path.is_empty() && !path.ends_with('\\') && !path.ends_with('/') {
                        path.push('\\');
                    }
                    path.push_str(&more);
                    let _ = self.write_wide_string_to_memory(buffer, 0x208, &path)?;
                    Ok(1)
                }
                ("shlwapi.dll", "PathCombineW") => {
                    let base = self.read_wide_string_from_memory(ctx.raw(1))?;
                    let more = self.read_wide_string_from_memory(ctx.raw(2))?;
                    let joined = if base.is_empty() {
                        more
                    } else if more.is_empty() {
                        base
                    } else {
                        format!("{}\\{}", base.trim_end_matches(['\\', '/']), more)
                    };
                    let _ = self.write_wide_string_to_memory(ctx.raw(0), 0x208, &joined)?;
                    Ok(ctx.raw(0))
                }
                ("shlwapi.dll", "PathFileExistsW") => {
                    let path = self.read_wide_string_from_memory(ctx.raw(0))?;
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
                    let buffer = ctx.raw(0);
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
                ("shlwapi.dll", "PathFindFileNameW") => self.path_find_file_name_w(ctx.raw(0)),
                ("shlwapi.dll", "PathRemoveFileSpecW") => {
                    let buffer = ctx.raw(0);
                    let mut path =
                        std::path::PathBuf::from(self.read_wide_string_from_memory(buffer)?);
                    let result = path.pop();
                    let _ =
                        self.write_wide_string_to_memory(buffer, 0x208, &path.to_string_lossy())?;
                    Ok(result as u64)
                }
                ("shlwapi.dll", "StrCmpIW") => {
                    let left = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let right = self.read_wide_string_from_memory(ctx.raw(1))?;
                    Ok(compare_ci(&left, &right) as u32 as u64)
                }
                ("shlwapi.dll", "StrCmpNIW") => {
                    let count = ctx.raw(2) as usize;
                    let left = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let right = self.read_wide_string_from_memory(ctx.raw(1))?;
                    Ok(compare_ci(
                        &left.chars().take(count).collect::<String>(),
                        &right.chars().take(count).collect::<String>(),
                    ) as u32 as u64)
                }
                ("shlwapi.dll", "StrTrimA") => {
                    let buffer = ctx.raw(0);
                    let text = self.read_c_string_from_memory(buffer)?;
                    let trim_chars = self.read_c_string_from_memory(ctx.raw(1))?;
                    let trimmed = text.trim_matches(|ch| trim_chars.contains(ch)).to_string();
                    let _ = self.write_c_string_to_memory(buffer, 0x1000, &trimmed)?;
                    Ok(1)
                }
                ("shlwapi.dll", "StrRChrW") => {
                    let haystack = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let target = char::from_u32(ctx.raw(2) as u32).unwrap_or('\0');
                    if let Some(index) = haystack.rfind(target) {
                        let offset = haystack[..index].encode_utf16().count() as u64 * 2;
                        Ok(ctx.raw(0) + offset)
                    } else {
                        Ok(0)
                    }
                }
                ("shlwapi.dll", "StrStrIA") => {
                    let haystack = self.read_c_string_from_memory(ctx.raw(0))?;
                    let needle = self.read_c_string_from_memory(ctx.raw(1))?;
                    if let Some(index) = haystack
                        .to_ascii_lowercase()
                        .find(&needle.to_ascii_lowercase())
                    {
                        Ok(ctx.raw(0) + index as u64)
                    } else {
                        Ok(0)
                    }
                }
                ("shlwapi.dll", "StrStrIW") => {
                    let haystack = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let needle = self.read_wide_string_from_memory(ctx.raw(1))?;
                    if let Some(index) = haystack
                        .to_ascii_lowercase()
                        .find(&needle.to_ascii_lowercase())
                    {
                        let offset = haystack[..index].encode_utf16().count() as u64 * 2;
                        Ok(ctx.raw(0) + offset)
                    } else {
                        Ok(0)
                    }
                }
                ("shlwapi.dll", "HashData") => {
                    let data_ptr = ctx.raw(0);
                    let data_len = ctx.raw(1) as usize;
                    let hash_ptr = ctx.raw(2);
                    let hash_len = ctx.raw(3) as usize;
                    if (data_len != 0 && data_ptr == 0) || (hash_len != 0 && hash_ptr == 0) {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(E_INVALIDARG_HRESULT);
                    }
                    let data = if data_len == 0 {
                        Vec::new()
                    } else {
                        self.read_bytes_from_memory(data_ptr, data_len)?
                    };
                    if hash_len != 0 {
                        let mut produced = Vec::with_capacity(hash_len);
                        let mut block = Sha256::digest(&data).to_vec();
                        while produced.len() < hash_len {
                            let remaining = hash_len - produced.len();
                            let take = remaining.min(block.len());
                            produced.extend_from_slice(&block[..take]);
                            if produced.len() < hash_len {
                                let mut hasher = Sha256::new();
                                hasher.update(&block);
                                hasher.update(&data);
                                hasher.update(&(produced.len() as u64).to_le_bytes());
                                block = hasher.finalize().to_vec();
                            }
                        }
                        self.core.modules.memory_mut().write(hash_ptr, &produced)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
