use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_winhttp_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("winhttp.dll", "WinHttpOpen") => true,
            ("winhttp.dll", "WinHttpConnect") => true,
            ("winhttp.dll", "WinHttpOpenRequest") => true,
            ("winhttp.dll", "WinHttpAddRequestHeaders") => true,
            ("winhttp.dll", "WinHttpSendRequest") => true,
            ("winhttp.dll", "WinHttpWriteData") => true,
            ("winhttp.dll", "WinHttpReceiveResponse") => true,
            ("winhttp.dll", "WinHttpReadData") => true,
            ("winhttp.dll", "WinHttpQueryDataAvailable") => true,
            ("winhttp.dll", "WinHttpQueryHeaders") => true,
            ("winhttp.dll", "WinHttpSetOption") => true,
            ("winhttp.dll", "WinHttpQueryOption") => true,
            ("winhttp.dll", "WinHttpSetTimeouts") => true,
            ("winhttp.dll", "WinHttpGetIEProxyConfigForCurrentUser") => true,
            ("winhttp.dll", "WinHttpGetProxyForUrl") => true,
            ("winhttp.dll", "WinHttpCloseHandle") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("winhttp.dll", "WinHttpOpen") => Ok(self.network.internet_open(
                    &self.read_optional_wide_text(arg(args, 0))?,
                    arg(args, 1) as u32,
                    &self.read_optional_wide_text(arg(args, 2))?,
                    &self.read_optional_wide_text(arg(args, 3))?,
                ) as u64),
                ("winhttp.dll", "WinHttpConnect") => {
                    let handle = self.network.internet_connect(
                        arg(args, 0) as u32,
                        &self.read_optional_wide_text(arg(args, 1))?,
                        arg(args, 2) as u16,
                        3,
                        "",
                        "",
                    );
                    self.log_http_connect_event("WinHttpConnect", handle)?;
                    Ok(handle as u64)
                }
                ("winhttp.dll", "WinHttpOpenRequest") => {
                    let handle = self.network.open_request(
                        arg(args, 0) as u32,
                        non_empty(&self.read_optional_wide_text(arg(args, 1))?).unwrap_or("GET"),
                        &self.read_optional_wide_text(arg(args, 2))?,
                        non_empty(&self.read_optional_wide_text(arg(args, 3))?)
                            .unwrap_or("HTTP/1.1"),
                        &self.read_optional_wide_text(arg(args, 4))?,
                        "",
                    );
                    self.apply_configured_http_response(handle)?;
                    Ok(handle as u64)
                }
                ("winhttp.dll", "WinHttpAddRequestHeaders") => {
                    let handle = arg(args, 0) as u32;
                    let headers = self.read_optional_wide_text(arg(args, 1))?;
                    Ok(self
                        .network
                        .with_request_mut(handle, |request| {
                            request.headers = Self::merge_http_headers(&request.headers, &headers);
                        })
                        .map(|_| 1)
                        .unwrap_or(0))
                }
                ("winhttp.dll", "WinHttpSendRequest") => {
                    let handle = arg(args, 0) as u32;
                    let headers = self.read_optional_wide_text(arg(args, 1))?;
                    let optional = if arg(args, 3) == 0 || arg(args, 4) == 0 {
                        Vec::new()
                    } else {
                        self.read_bytes_from_memory(arg(args, 3), arg(args, 4) as usize)?
                    };
                    let sent = self
                        .network
                        .with_request_mut(handle, |request| {
                            request.headers = Self::merge_http_headers(&request.headers, &headers);
                            if !optional.is_empty() {
                                request.request_body = optional.clone();
                            }
                            request.sent = true;
                        })
                        .map(|_| 1)
                        .unwrap_or(0);
                    if sent != 0 {
                        self.log_http_request_event("WinHttpSendRequest", handle)?;
                    }
                    Ok(sent)
                }
                ("winhttp.dll", "WinHttpWriteData") => {
                    let handle = arg(args, 0) as u32;
                    let data = if arg(args, 1) == 0 || arg(args, 2) == 0 {
                        Vec::new()
                    } else {
                        self.read_bytes_from_memory(arg(args, 1), arg(args, 2) as usize)?
                    };
                    let written = self
                        .network
                        .with_request_mut(handle, |request| {
                            request.request_body.extend_from_slice(&data);
                            request.sent = true;
                        })
                        .map(|_| 1)
                        .unwrap_or(0);
                    if arg(args, 3) != 0 {
                        self.write_u32(arg(args, 3), arg(args, 2) as u32)?;
                    }
                    if written != 0 {
                        self.log_http_request_event("WinHttpWriteData", handle)?;
                    }
                    Ok(written)
                }
                ("winhttp.dll", "WinHttpReceiveResponse") => {
                    Ok(self.network.get_request(arg(args, 0) as u32).is_some() as u64)
                }
                ("winhttp.dll", "WinHttpReadData") => {
                    let data = self
                        .network
                        .request_read(arg(args, 0) as u32, arg(args, 2) as usize);
                    if arg(args, 1) != 0 && !data.is_empty() {
                        self.modules.memory_mut().write(arg(args, 1), &data)?;
                    }
                    if arg(args, 3) != 0 {
                        self.write_u32(arg(args, 3), data.len() as u32)?;
                    }
                    Ok(1)
                }
                ("winhttp.dll", "WinHttpQueryDataAvailable") => {
                    if arg(args, 1) != 0 {
                        self.write_u32(
                            arg(args, 1),
                            self.network.request_remaining(arg(args, 0) as u32) as u32,
                        )?;
                    }
                    Ok(1)
                }
                ("winhttp.dll", "WinHttpQueryHeaders") => {
                    let Some(value) =
                        self.winhttp_query_response_value(arg(args, 0) as u32, arg(args, 1) as u32)
                    else {
                        return Ok(0);
                    };
                    if arg(args, 4) != 0 {
                        self.write_u32(arg(args, 4), value.len() as u32)?;
                    }
                    if arg(args, 3) != 0 {
                        self.modules.memory_mut().write(arg(args, 3), &value)?;
                    }
                    Ok(1)
                }
                ("winhttp.dll", "WinHttpSetOption") => Ok(1),
                ("winhttp.dll", "WinHttpQueryOption") => {
                    if arg(args, 3) != 0 {
                        self.write_u32(arg(args, 3), 4)?;
                    }
                    if arg(args, 2) != 0 {
                        self.write_u32(arg(args, 2), 0)?;
                    }
                    Ok(1)
                }
                ("winhttp.dll", "WinHttpSetTimeouts") => Ok(1),
                ("winhttp.dll", "WinHttpGetIEProxyConfigForCurrentUser") => {
                    let config_ptr = arg(args, 0);
                    if config_ptr == 0 {
                        return Ok(0);
                    }
                    self.write_u32(config_ptr, 0)?;
                    if self.arch.is_x64() {
                        self.write_u32(config_ptr + 4, 0)?;
                    }
                    let pointer_base = if self.arch.is_x86() {
                        config_ptr + 4
                    } else {
                        config_ptr + 8
                    };
                    self.write_pointer_value(pointer_base, 0)?;
                    self.write_pointer_value(pointer_base + self.arch.pointer_size as u64, 0)?;
                    self.write_pointer_value(
                        pointer_base + (self.arch.pointer_size as u64 * 2),
                        0,
                    )?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("winhttp.dll", "WinHttpGetProxyForUrl") => {
                    let info_ptr = arg(args, 3);
                    if info_ptr == 0 {
                        return Ok(0);
                    }
                    self.write_u32(info_ptr, WINHTTP_ACCESS_TYPE_NO_PROXY)?;
                    if self.arch.is_x64() {
                        self.write_u32(info_ptr + 4, 0)?;
                    }
                    let pointer_base = if self.arch.is_x86() {
                        info_ptr + 4
                    } else {
                        info_ptr + 8
                    };
                    self.write_pointer_value(pointer_base, 0)?;
                    self.write_pointer_value(pointer_base + self.arch.pointer_size as u64, 0)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("winhttp.dll", "WinHttpCloseHandle") => {
                    Ok(self.network.close_internet_handle(arg(args, 0) as u32) as u64)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
