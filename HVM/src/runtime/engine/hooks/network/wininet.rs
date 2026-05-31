use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_wininet_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("wininet.dll", "InternetOpenA") => true,
            ("wininet.dll", "InternetOpenW") => true,
            ("wininet.dll", "InternetConnectA") => true,
            ("wininet.dll", "InternetConnectW") => true,
            ("wininet.dll", "InternetOpenUrlA") => true,
            ("wininet.dll", "InternetOpenUrlW") => true,
            ("wininet.dll", "HttpOpenRequestA") => true,
            ("wininet.dll", "HttpOpenRequestW") => true,
            ("wininet.dll", "HttpSendRequestA") => true,
            ("wininet.dll", "HttpSendRequestW") => true,
            ("wininet.dll", "InternetCanonicalizeUrlA") => true,
            ("wininet.dll", "InternetCanonicalizeUrlW") => true,
            ("wininet.dll", "InternetReadFile") => true,
            ("wininet.dll", "InternetCloseHandle") => true,
            ("wininet.dll", "InternetSetOptionA") | ("wininet.dll", "InternetSetOptionW") => true,
            ("wininet.dll", "InternetQueryOptionA") | ("wininet.dll", "InternetQueryOptionW") => {
                true
            }
            ("wininet.dll", "InternetCrackUrlA") => true,
            ("wininet.dll", "InternetCrackUrlW") => true,
            ("wininet.dll", "InternetGetConnectedState") => true,
            ("wininet.dll", "InternetQueryDataAvailable") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("wininet.dll", "InternetOpenA") => {
                    let handle = self.network_state.network.internet_open(
                        &self.read_c_string_from_memory(ctx.raw(0))?,
                        ctx.raw(1) as u32,
                        &self.read_c_string_from_memory(ctx.raw(2))?,
                        &self.read_c_string_from_memory(ctx.raw(3))?,
                    );
                    Ok(handle as u64)
                }
                ("wininet.dll", "InternetOpenW") => {
                    let handle = self.network_state.network.internet_open(
                        &self.read_wide_string_from_memory(ctx.raw(0))?,
                        ctx.raw(1) as u32,
                        &self.read_wide_string_from_memory(ctx.raw(2))?,
                        &self.read_wide_string_from_memory(ctx.raw(3))?,
                    );
                    Ok(handle as u64)
                }
                ("wininet.dll", "InternetConnectA") => {
                    let handle = self.network_state.network.internet_connect(
                        ctx.raw(0) as u32,
                        &self.read_c_string_from_memory(ctx.raw(1))?,
                        ctx.raw(2) as u16,
                        ctx.raw(5) as u32,
                        &self.read_c_string_from_memory(ctx.raw(3))?,
                        &self.read_c_string_from_memory(ctx.raw(4))?,
                    );
                    self.log_http_connect_event("InternetConnectA", handle)?;
                    Ok(handle as u64)
                }
                ("wininet.dll", "InternetConnectW") => {
                    let handle = self.network_state.network.internet_connect(
                        ctx.raw(0) as u32,
                        &self.read_wide_string_from_memory(ctx.raw(1))?,
                        ctx.raw(2) as u16,
                        ctx.raw(5) as u32,
                        &self.read_wide_string_from_memory(ctx.raw(3))?,
                        &self.read_wide_string_from_memory(ctx.raw(4))?,
                    );
                    self.log_http_connect_event("InternetConnectW", handle)?;
                    Ok(handle as u64)
                }
                ("wininet.dll", "InternetOpenUrlA") => {
                    let handle = self.network_state.network.open_request(
                        ctx.raw(0) as u32,
                        "GET",
                        &self.read_c_string_from_memory(ctx.raw(1))?,
                        "HTTP/1.1",
                        "",
                        &self.read_c_string_from_memory(ctx.raw(2))?,
                    );
                    let _ = self
                        .network_state
                        .network
                        .with_request_mut(handle, |request| request.sent = true);
                    self.apply_configured_http_response(handle)?;
                    self.log_http_request_event("InternetOpenUrlA", handle)?;
                    Ok(handle as u64)
                }
                ("wininet.dll", "InternetOpenUrlW") => {
                    let handle = self.network_state.network.open_request(
                        ctx.raw(0) as u32,
                        "GET",
                        &self.read_wide_string_from_memory(ctx.raw(1))?,
                        "HTTP/1.1",
                        "",
                        &self.read_wide_string_from_memory(ctx.raw(2))?,
                    );
                    let _ = self
                        .network_state
                        .network
                        .with_request_mut(handle, |request| request.sent = true);
                    self.apply_configured_http_response(handle)?;
                    self.log_http_request_event("InternetOpenUrlW", handle)?;
                    Ok(handle as u64)
                }
                ("wininet.dll", "HttpOpenRequestA") => {
                    let handle = self.network_state.network.open_request(
                        ctx.raw(0) as u32,
                        non_empty(&self.read_c_string_from_memory(ctx.raw(1))?).unwrap_or("GET"),
                        &self.read_c_string_from_memory(ctx.raw(2))?,
                        non_empty(&self.read_c_string_from_memory(ctx.raw(3))?)
                            .unwrap_or("HTTP/1.1"),
                        &self.read_c_string_from_memory(ctx.raw(4))?,
                        "",
                    );
                    self.apply_configured_http_response(handle)?;
                    Ok(handle as u64)
                }
                ("wininet.dll", "HttpOpenRequestW") => {
                    let handle = self.network_state.network.open_request(
                        ctx.raw(0) as u32,
                        non_empty(&self.read_wide_string_from_memory(ctx.raw(1))?).unwrap_or("GET"),
                        &self.read_wide_string_from_memory(ctx.raw(2))?,
                        non_empty(&self.read_wide_string_from_memory(ctx.raw(3))?)
                            .unwrap_or("HTTP/1.1"),
                        &self.read_wide_string_from_memory(ctx.raw(4))?,
                        "",
                    );
                    self.apply_configured_http_response(handle)?;
                    Ok(handle as u64)
                }
                ("wininet.dll", "HttpSendRequestA") => {
                    let handle = ctx.raw(0) as u32;
                    let headers = if ctx.raw(1) != 0 {
                        self.read_c_string_from_memory(ctx.raw(1))?
                    } else {
                        String::new()
                    };
                    let optional = if ctx.raw(3) == 0 || ctx.raw(4) == 0 {
                        Vec::new()
                    } else {
                        self.read_bytes_from_memory(ctx.raw(3), ctx.raw(4) as usize)?
                    };
                    let sent = self
                        .network_state
                        .network
                        .with_request_mut(handle, |request| {
                            if !headers.is_empty() {
                                request.headers = headers;
                            }
                            if !optional.is_empty() {
                                request.request_body = optional.clone();
                            }
                            request.sent = true;
                        })
                        .map(|_| 1)
                        .unwrap_or(0);
                    if sent != 0 {
                        self.log_http_request_event("HttpSendRequestA", handle)?;
                    }
                    Ok(sent)
                }
                ("wininet.dll", "HttpSendRequestW") => {
                    let handle = ctx.raw(0) as u32;
                    let headers = if ctx.raw(1) != 0 {
                        self.read_wide_string_from_memory(ctx.raw(1))?
                    } else {
                        String::new()
                    };
                    let optional = if ctx.raw(3) == 0 || ctx.raw(4) == 0 {
                        Vec::new()
                    } else {
                        self.read_bytes_from_memory(ctx.raw(3), ctx.raw(4) as usize)?
                    };
                    let sent = self
                        .network_state
                        .network
                        .with_request_mut(handle, |request| {
                            if !headers.is_empty() {
                                request.headers = headers;
                            }
                            if !optional.is_empty() {
                                request.request_body = optional.clone();
                            }
                            request.sent = true;
                        })
                        .map(|_| 1)
                        .unwrap_or(0);
                    if sent != 0 {
                        self.log_http_request_event("HttpSendRequestW", handle)?;
                    }
                    Ok(sent)
                }
                ("wininet.dll", "InternetCanonicalizeUrlA") => {
                    self.internet_canonicalize_url(false, ctx.raw(0), ctx.raw(1), ctx.raw(2))
                }
                ("wininet.dll", "InternetCanonicalizeUrlW") => {
                    self.internet_canonicalize_url(true, ctx.raw(0), ctx.raw(1), ctx.raw(2))
                }
                ("wininet.dll", "InternetReadFile") => {
                    let data = self
                        .network_state
                        .network
                        .request_read(ctx.raw(0) as u32, ctx.raw(2) as usize);
                    if ctx.raw(1) != 0 && !data.is_empty() {
                        self.core.modules.memory_mut().write(ctx.raw(1), &data)?;
                    }
                    if ctx.raw(3) != 0 {
                        self.write_u32(ctx.raw(3), data.len() as u32)?;
                    }
                    Ok(1)
                }
                ("wininet.dll", "InternetCloseHandle") => Ok(self
                    .network_state
                    .network
                    .close_internet_handle(ctx.raw(0) as u32)
                    as u64),
                ("wininet.dll", "InternetSetOptionA") | ("wininet.dll", "InternetSetOptionW") => {
                    Ok(1)
                }
                ("wininet.dll", "InternetQueryOptionA")
                | ("wininet.dll", "InternetQueryOptionW") => {
                    if ctx.raw(3) != 0 {
                        self.write_u32(ctx.raw(3), 4)?;
                    }
                    if ctx.raw(2) != 0 {
                        self.write_u32(ctx.raw(2), 0)?;
                    }
                    Ok(1)
                }
                ("wininet.dll", "InternetCrackUrlA") => {
                    self.internet_crack_url(false, ctx.raw(0), ctx.raw(1), ctx.raw(3))
                }
                ("wininet.dll", "InternetCrackUrlW") => {
                    self.internet_crack_url(true, ctx.raw(0), ctx.raw(1), ctx.raw(3))
                }
                ("wininet.dll", "InternetGetConnectedState") => {
                    if ctx.raw(0) != 0 {
                        self.write_u32(ctx.raw(0), 1)?;
                    }
                    Ok(1)
                }
                ("wininet.dll", "InternetQueryDataAvailable") => {
                    if ctx.raw(1) != 0 {
                        self.write_u32(
                            ctx.raw(1),
                            self.network_state
                                .network
                                .request_remaining(ctx.raw(0) as u32)
                                as u32,
                        )?;
                    }
                    Ok(1)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
