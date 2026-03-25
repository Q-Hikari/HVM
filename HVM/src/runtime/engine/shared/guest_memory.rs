use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn capture_stack_args(
        &self,
        first_arg: u64,
        argc: usize,
    ) -> Result<Vec<u64>, VmError> {
        (0..argc)
            .map(|index| {
                self.read_u32(first_arg + index as u64 * 4)
                    .map(|value| value as u64)
            })
            .collect()
    }

    pub(in crate::runtime::engine) fn read_optional_wide_text(
        &self,
        address: u64,
    ) -> Result<String, VmError> {
        if address == 0 {
            Ok(String::new())
        } else {
            self.read_wide_string_from_memory(address)
        }
    }

    pub(in crate::runtime::engine) fn read_wide_string_from_memory(
        &self,
        address: u64,
    ) -> Result<String, VmError> {
        if address == 0 {
            return Ok(String::new());
        }
        let mut bytes = Vec::new();
        let mut offset = 0u64;
        let mut remaining = 0x1000usize;
        while remaining >= 2 {
            let cursor = address + offset;
            let region_end = self
                .modules
                .memory()
                .find_region(cursor, 1)
                .ok_or(crate::error::MemoryError::MissingRegion {
                    address: cursor,
                    size: 1,
                })?
                .end();
            let available = (region_end - cursor) as usize;
            let chunk_size = remaining.min(available).min(0x400) & !1usize;
            if chunk_size == 0 {
                break;
            }
            let chunk = self.read_bytes_from_memory(cursor, chunk_size)?;
            let mut terminator = None;
            for index in (0..chunk.len()).step_by(2) {
                if chunk[index..index + 2] == [0, 0] {
                    terminator = Some(index);
                    break;
                }
            }
            if let Some(index) = terminator {
                bytes.extend_from_slice(&chunk[..index]);
                break;
            }
            bytes.extend_from_slice(&chunk);
            offset += chunk_size as u64;
            remaining = remaining.saturating_sub(chunk_size);
        }
        Ok(Self::decode_utf16le_bytes_ignoring_errors(&bytes))
    }

    pub(in crate::runtime::engine) fn read_c_string_from_memory(
        &self,
        address: u64,
    ) -> Result<String, VmError> {
        Ok(Self::decode_ascii_bytes_ignoring_errors(
            &self.read_c_string_bytes_from_memory(address)?,
        ))
    }

    pub(in crate::runtime::engine) fn read_c_string_bytes_from_memory(
        &self,
        address: u64,
    ) -> Result<Vec<u8>, VmError> {
        if address == 0 {
            return Ok(Vec::new());
        }
        let mut bytes = Vec::new();
        let mut offset = 0u64;
        let mut remaining = 0x1000usize;
        while remaining > 0 {
            let cursor = address + offset;
            let region_end = self
                .modules
                .memory()
                .find_region(cursor, 1)
                .ok_or(crate::error::MemoryError::MissingRegion {
                    address: cursor,
                    size: 1,
                })?
                .end();
            let available = (region_end - cursor) as usize;
            let chunk_size = remaining.min(available).min(0x400);
            let chunk = self.read_bytes_from_memory(cursor, chunk_size)?;
            if let Some(index) = chunk.iter().position(|byte| *byte == 0) {
                bytes.extend_from_slice(&chunk[..index]);
                break;
            }
            bytes.extend_from_slice(&chunk);
            offset += chunk_size as u64;
            remaining = remaining.saturating_sub(chunk_size);
        }
        Ok(bytes)
    }

    pub(in crate::runtime::engine) fn read_bytes_from_memory(
        &self,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, VmError> {
        self.modules
            .memory()
            .read(address, size)
            .map_err(VmError::from)
    }

    pub(in crate::runtime::engine) fn read_wide_counted_string_from_memory(
        &self,
        address: u64,
        char_count: usize,
    ) -> Result<String, VmError> {
        if address == 0 || char_count == 0 {
            return Ok(String::new());
        }
        let bytes = self.read_bytes_from_memory(address, char_count * 2)?;
        Ok(Self::decode_utf16le_bytes_ignoring_errors(&bytes))
    }

    pub(in crate::runtime::engine) fn read_ansi_input(
        &self,
        address: u64,
        count: u64,
    ) -> Result<Vec<u8>, VmError> {
        if address == 0 {
            return Ok(Vec::new());
        }
        if count == u32::MAX as u64 {
            return self.read_c_string_bytes_from_memory(address);
        }
        self.read_bytes_from_memory(address, count as usize)
    }

    pub(in crate::runtime::engine) fn read_wide_input_string(
        &self,
        address: u64,
        count: u64,
    ) -> Result<String, VmError> {
        if address == 0 {
            return Ok(String::new());
        }
        if count == u32::MAX as u64 {
            return self.read_wide_string_from_memory(address);
        }
        self.read_wide_counted_string_from_memory(address, count as usize)
    }

    pub(in crate::runtime::engine) fn read_provider_name(
        &self,
        value: u64,
    ) -> Result<String, VmError> {
        if value == 0 {
            return Ok(String::new());
        }
        if value <= 0xFFFF {
            return Ok(format!("provider:{value}"));
        }
        let wide = self.read_wide_string_from_memory(value)?;
        if !wide.is_empty() {
            return Ok(wide);
        }
        self.read_c_string_from_memory(value)
    }

    pub(in crate::runtime::engine) fn current_tls_thread_id(&self) -> u32 {
        self.scheduler
            .current_tid()
            .or(self.main_thread_tid)
            .unwrap_or(0)
    }

    pub(in crate::runtime::engine) fn decode_ascii_bytes_ignoring_errors(bytes: &[u8]) -> String {
        bytes
            .iter()
            .copied()
            .filter(u8::is_ascii)
            .map(char::from)
            .collect()
    }

    pub(in crate::runtime::engine) fn decode_utf16le_bytes_ignoring_errors(bytes: &[u8]) -> String {
        std::char::decode_utf16(
            bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])),
        )
        .filter_map(Result::ok)
        .collect()
    }

    pub(in crate::runtime::engine) fn decode_gbk_bytes_ignoring_errors(bytes: &[u8]) -> String {
        let mut text = String::new();
        let mut index = 0usize;
        while index < bytes.len() {
            let lead = bytes[index];
            if lead < 0x80 {
                text.push(char::from(lead));
                index += 1;
                continue;
            }
            if !(0x81..=0xFE).contains(&lead) {
                index += 1;
                continue;
            }
            let Some(&trail) = bytes.get(index + 1) else {
                break;
            };
            if !matches!(trail, 0x40..=0x7E | 0x80..=0xFE) {
                index += 1;
                continue;
            }

            let trail_offset = if trail < 0x7F { 0x40 } else { 0x41 };
            let table_index = (u16::from(lead) - 0x81) * 190 + (u16::from(trail) - trail_offset);
            if !python_gbk_pair_is_valid(table_index) {
                index += 1;
                continue;
            }
            let code_point = gbk_index::forward(table_index);
            if code_point != 0xFFFF {
                if let Some(ch) = char::from_u32(code_point) {
                    text.push(ch);
                    index += 2;
                    continue;
                }
            }

            // Python's `gbk` decoder drops the invalid lead byte but still
            // retries the trailing byte as a fresh input byte.
            index += 1;
        }
        text
    }

    fn effective_code_page(&self, code_page: u64) -> u64 {
        match code_page {
            0 | 1 => self.ansi_code_page(),
            3 => self.oem_code_page(),
            _ => code_page,
        }
    }

    pub(in crate::runtime::engine) fn code_page_encoding(
        &self,
        code_page: u64,
    ) -> Option<EncodingRef> {
        match code_page {
            936 => Some(GBK),
            2 => Some(MAC_ROMAN),
            1200 => Some(UTF_16LE),
            1252 => Some(WINDOWS_1252),
            65001 => Some(UTF_8),
            _ => None,
        }
    }

    pub(in crate::runtime::engine) fn decode_code_page_bytes(
        &self,
        code_page: u64,
        bytes: &[u8],
    ) -> String {
        match self.effective_code_page(code_page) {
            936 => Self::decode_gbk_bytes_ignoring_errors(bytes),
            1200 => Self::decode_utf16le_bytes_ignoring_errors(bytes),
            65000 => String::from_utf8_lossy(bytes)
                .chars()
                .filter(|ch| *ch != '\u{FFFD}')
                .collect(),
            _ => {
                if let Some(encoding) = self.code_page_encoding(code_page) {
                    return encoding
                        .decode(bytes, DecoderTrap::Ignore)
                        .unwrap_or_else(|_| {
                            String::from_utf8_lossy(bytes)
                                .chars()
                                .filter(|ch| *ch != '\u{FFFD}')
                                .collect()
                        });
                }
                String::from_utf8_lossy(bytes)
                    .chars()
                    .filter(|ch| *ch != '\u{FFFD}')
                    .collect()
            }
        }
    }

    pub(in crate::runtime::engine) fn encode_code_page_string(
        &self,
        code_page: u64,
        text: &str,
    ) -> Vec<u8> {
        match self.effective_code_page(code_page) {
            1200 => text
                .encode_utf16()
                .flat_map(|word| word.to_le_bytes())
                .collect(),
            65000 => text.as_bytes().to_vec(),
            _ => {
                if let Some(encoding) = self.code_page_encoding(code_page) {
                    return encoding
                        .encode(text, EncoderTrap::Ignore)
                        .unwrap_or_else(|_| text.as_bytes().to_vec());
                }
                text.as_bytes().to_vec()
            }
        }
    }

    pub(in crate::runtime::engine) fn write_c_string_to_memory(
        &mut self,
        address: u64,
        capacity: usize,
        value: &str,
    ) -> Result<u64, VmError> {
        if address == 0 || capacity == 0 {
            return Ok(0);
        }
        let writable = capacity.saturating_sub(1);
        let data = &value.as_bytes()[..value.len().min(writable)];
        self.modules.memory_mut().write(address, data)?;
        self.modules
            .memory_mut()
            .write(address + data.len() as u64, &[0])?;
        Ok(data.len() as u64)
    }

    pub(in crate::runtime::engine) fn write_raw_bytes_to_memory(
        &mut self,
        address: u64,
        capacity: usize,
        value: &[u8],
    ) -> Result<u64, VmError> {
        if address == 0 || capacity == 0 {
            return Ok(0);
        }
        let writable = capacity.min(value.len());
        self.modules
            .memory_mut()
            .write(address, &value[..writable])?;
        Ok(writable as u64)
    }

    pub(in crate::runtime::engine) fn write_wide_string_to_memory(
        &mut self,
        address: u64,
        capacity: usize,
        value: &str,
    ) -> Result<u64, VmError> {
        if address == 0 || capacity == 0 {
            return Ok(0);
        }
        let mut encoded = value.encode_utf16().collect::<Vec<_>>();
        let writable = capacity.saturating_sub(1);
        encoded.truncate(writable);
        let bytes = encoded
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        self.modules.memory_mut().write(address, &bytes)?;
        self.modules
            .memory_mut()
            .write(address + bytes.len() as u64, &[0, 0])?;
        Ok(encoded.len() as u64)
    }

    pub(in crate::runtime::engine) fn alloc_bstr_from_wide_ptr(
        &mut self,
        source: u64,
        explicit_len: Option<usize>,
        source_name: &str,
    ) -> Result<u64, VmError> {
        if source == 0 && explicit_len.unwrap_or(0) == 0 {
            return Ok(0);
        }

        let units = if let Some(len) = explicit_len {
            if source == 0 {
                vec![0u16; len]
            } else {
                let bytes = self.read_bytes_from_memory(source, len.saturating_mul(2))?;
                bytes
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect::<Vec<_>>()
            }
        } else {
            self.read_wide_string_from_memory(source)?
                .encode_utf16()
                .collect::<Vec<_>>()
        };

        let byte_len = units.len().saturating_mul(2);
        let base = self.alloc_process_heap_block((byte_len + 6) as u64, source_name)?;
        self.write_u32(base, byte_len as u32)?;
        let bytes = units
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        if !bytes.is_empty() {
            self.modules.memory_mut().write(base + 4, &bytes)?;
        }
        self.modules
            .memory_mut()
            .write(base + 4 + byte_len as u64, &[0, 0])?;
        Ok(base + 4)
    }

    pub(in crate::runtime::engine) fn read_bstr_byte_len(&self, bstr: u64) -> Result<u32, VmError> {
        if bstr == 0 || bstr < 4 {
            return Ok(0);
        }
        self.read_u32(bstr - 4)
    }

    pub(in crate::runtime::engine) fn free_bstr(&mut self, bstr: u64) -> bool {
        if bstr < 4 {
            return false;
        }
        self.heaps.free(self.heaps.process_heap(), bstr - 4)
    }

    pub(in crate::runtime::engine) fn ensure_shell_imalloc(&mut self) -> Result<u64, VmError> {
        if let Some(object) = self.shell_imalloc {
            return Ok(object);
        }

        let methods = [
            "IMalloc_QueryInterface",
            "IMalloc_AddRef",
            "IMalloc_Release",
            "IMalloc_Alloc",
            "IMalloc_Realloc",
            "IMalloc_Free",
            "IMalloc_GetSize",
            "IMalloc_DidAlloc",
            "IMalloc_HeapMinimize",
        ];
        let shell32_base = self
            .modules
            .get_loaded("shell32.dll")
            .map(|module| module.base)
            .ok_or(VmError::RuntimeInvariant(
                "shell32.dll not loaded for SHGetMalloc",
            ))?;
        let vtable = self.alloc_process_heap_block((methods.len() * 4) as u64, "IMalloc:vtable")?;
        for (index, method) in methods.iter().enumerate() {
            let stub = self.modules.resolve_export(
                shell32_base,
                &self.config,
                &mut self.hooks,
                Some(method),
                None,
            );
            self.write_u32(vtable + (index * 4) as u64, stub as u32)?;
        }

        let object = self.alloc_process_heap_block(8, "IMalloc:object")?;
        self.write_u32(object, vtable as u32)?;
        self.write_u32(object + 4, 1)?;
        self.shell_imalloc = Some(object);
        Ok(object)
    }

    pub(in crate::runtime::engine) fn alloc_process_heap_block(
        &mut self,
        size: u64,
        source: &str,
    ) -> Result<u64, VmError> {
        let size = size.max(1);
        let address = self
            .heaps
            .alloc(self.modules.memory_mut(), self.heaps.process_heap(), size)
            .ok_or(VmError::RuntimeInvariant("process heap allocation failed"))?;
        self.log_heap_event(
            "HEAP_ALLOC",
            self.heaps.process_heap(),
            address,
            size,
            source,
        )?;
        Ok(address)
    }

    pub(in crate::runtime::engine) fn ensure_inet_ntoa_buffer(&mut self) -> Result<u64, VmError> {
        if let Some(address) = self.inet_ntoa_buffer {
            return Ok(address);
        }
        let address = self.alloc_process_heap_block(32, "inet_ntoa")?;
        self.inet_ntoa_buffer = Some(address);
        Ok(address)
    }

    pub(in crate::runtime::engine) fn read_sockaddr(
        &self,
        address: u64,
        length: usize,
    ) -> Result<(String, u16, u16), VmError> {
        if address == 0 || length < 8 {
            return Ok(("0.0.0.0".to_string(), 0, 0));
        }
        let family = self.read_u16(address)?;
        let port = u16::from_be_bytes(
            self.read_bytes_from_memory(address + 2, 2)?
                .try_into()
                .unwrap(),
        );
        let ip = self.read_bytes_from_memory(address + 4, 4)?;
        Ok((
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            port,
            family,
        ))
    }

    pub(in crate::runtime::engine) fn write_sockaddr(
        &mut self,
        address: u64,
        host: &str,
        port: u16,
    ) -> Result<(), VmError> {
        if address == 0 {
            return Ok(());
        }
        let ip = self
            .resolve_ipv4_like_winsock(host)
            .unwrap_or(Ipv4Addr::new(0, 0, 0, 0))
            .octets();
        let mut payload = Vec::with_capacity(16);
        payload.extend_from_slice(&AF_INET.to_le_bytes());
        payload.extend_from_slice(&port.to_be_bytes());
        payload.extend_from_slice(&ip);
        payload.extend_from_slice(&[0u8; 8]);
        self.modules.memory_mut().write(address, &payload)?;
        Ok(())
    }

    pub(in crate::runtime::engine) fn fd_set_array_offset(&self) -> u64 {
        if self.arch.is_x86() {
            4
        } else {
            8
        }
    }

    pub(in crate::runtime::engine) fn read_fd_set_handles(
        &self,
        address: u64,
    ) -> Result<Vec<u32>, VmError> {
        if address == 0 {
            return Ok(Vec::new());
        }
        let count = self.read_u32(address)? as usize;
        let ptr_size = self.arch.pointer_size as u64;
        let offset = self.fd_set_array_offset();
        let mut handles = Vec::new();
        for index in 0..count.min(64) {
            let slot = address + offset + index as u64 * ptr_size;
            let value = if self.arch.is_x86() {
                self.read_u32(slot)? as u64
            } else {
                u64::from_le_bytes(self.read_bytes_from_memory(slot, 8)?.try_into().unwrap())
            };
            handles.push(value as u32);
        }
        Ok(handles)
    }

    pub(in crate::runtime::engine) fn write_fd_set_handles(
        &mut self,
        address: u64,
        handles: &[u32],
    ) -> Result<(), VmError> {
        if address == 0 {
            return Ok(());
        }
        self.write_u32(address, handles.len().min(64) as u32)?;
        if self.fd_set_array_offset() > 4 {
            self.modules.memory_mut().write(address + 4, &[0u8; 4])?;
        }
        let ptr_size = self.arch.pointer_size as u64;
        for (index, handle) in handles.iter().take(64).enumerate() {
            let slot = address + self.fd_set_array_offset() + index as u64 * ptr_size;
            self.write_pointer_value(slot, *handle as u64)?;
        }
        Ok(())
    }

    pub(in crate::runtime::engine) fn create_hostent(
        &mut self,
        name: &str,
        ip: &str,
    ) -> Result<u64, VmError> {
        let ptr_size = self.arch.pointer_size as u64;
        let host_name = if name.is_empty() { "localhost" } else { name };
        let name_bytes = format!("{host_name}\0").into_bytes();
        let ip_bytes = self
            .resolve_ipv4_like_winsock(ip)
            .unwrap_or_else(|| self.synthetic_host_ipv4(name))
            .octets();
        let name_ptr =
            self.alloc_process_heap_block(name_bytes.len() as u64, "gethostbyname:name")?;
        let addr_ptr =
            self.alloc_process_heap_block(ip_bytes.len() as u64, "gethostbyname:addr")?;
        let aliases_ptr = self.alloc_process_heap_block(ptr_size, "gethostbyname:aliases")?;
        let addr_list_ptr =
            self.alloc_process_heap_block(ptr_size * 2, "gethostbyname:addr_list")?;
        self.modules.memory_mut().write(name_ptr, &name_bytes)?;
        self.modules.memory_mut().write(addr_ptr, &ip_bytes)?;
        self.modules
            .memory_mut()
            .write(aliases_ptr, &vec![0u8; ptr_size as usize])?;
        self.write_pointer_value(addr_list_ptr, addr_ptr)?;
        self.write_pointer_value(addr_list_ptr + ptr_size, 0)?;
        let struct_size = if self.arch.is_x86() { 16 } else { 32 };
        let hostent_ptr = self.alloc_process_heap_block(struct_size, "gethostbyname:hostent")?;
        self.modules
            .memory_mut()
            .write(hostent_ptr, &vec![0u8; struct_size as usize])?;
        if self.arch.is_x86() {
            self.write_pointer_value(hostent_ptr, name_ptr)?;
            self.write_pointer_value(hostent_ptr + 4, aliases_ptr)?;
            self.write_u16(hostent_ptr + 8, AF_INET)?;
            self.write_u16(hostent_ptr + 10, 4)?;
            self.write_pointer_value(hostent_ptr + 12, addr_list_ptr)?;
        } else {
            self.write_pointer_value(hostent_ptr, name_ptr)?;
            self.write_pointer_value(hostent_ptr + 8, aliases_ptr)?;
            self.write_u16(hostent_ptr + 16, AF_INET)?;
            self.write_u16(hostent_ptr + 18, 4)?;
            self.write_pointer_value(hostent_ptr + 24, addr_list_ptr)?;
        }
        Ok(hostent_ptr)
    }

    pub(in crate::runtime::engine) fn create_addrinfo(
        &mut self,
        node_name: &str,
        service_name: &str,
    ) -> Result<u64, VmError> {
        let host = self.synthetic_host_ipv4_text(node_name);
        let port = service_name
            .parse::<u16>()
            .ok()
            .or_else(|| match service_name.to_ascii_lowercase().as_str() {
                "http" => Some(80),
                "https" => Some(443),
                _ => None,
            })
            .unwrap_or(0);
        let sockaddr_ptr = self.alloc_process_heap_block(16, "getaddrinfo:sockaddr")?;
        self.write_sockaddr(sockaddr_ptr, &host, port)?;
        let canon_name = format!(
            "{}\0",
            if node_name.trim().is_empty() {
                host.as_str()
            } else {
                node_name.trim()
            }
        );
        let canon_name_ptr =
            self.alloc_process_heap_block(canon_name.len() as u64, "getaddrinfo:canon")?;
        self.modules
            .memory_mut()
            .write(canon_name_ptr, canon_name.as_bytes())?;
        let struct_size = if self.arch.is_x86() { 32 } else { 48 };
        let addrinfo_ptr = self.alloc_process_heap_block(struct_size, "getaddrinfo:addrinfo")?;
        self.modules
            .memory_mut()
            .write(addrinfo_ptr, &vec![0u8; struct_size as usize])?;
        self.write_u32(addrinfo_ptr + 4, AF_INET as u32)?;
        self.write_u32(addrinfo_ptr + 8, 1)?;
        self.write_u32(addrinfo_ptr + 12, 6)?;
        if self.arch.is_x86() {
            self.write_u32(addrinfo_ptr + 16, 16)?;
            self.write_pointer_value(addrinfo_ptr + 20, canon_name_ptr)?;
            self.write_pointer_value(addrinfo_ptr + 24, sockaddr_ptr)?;
            self.write_pointer_value(addrinfo_ptr + 28, 0)?;
        } else {
            self.modules
                .memory_mut()
                .write(addrinfo_ptr + 16, &16u64.to_le_bytes())?;
            self.write_pointer_value(addrinfo_ptr + 24, canon_name_ptr)?;
            self.write_pointer_value(addrinfo_ptr + 32, sockaddr_ptr)?;
            self.write_pointer_value(addrinfo_ptr + 40, 0)?;
        }
        Ok(addrinfo_ptr)
    }

    pub(in crate::runtime::engine) fn wsabuf_pointer_offset(&self) -> u64 {
        if self.arch.is_x86() {
            4
        } else {
            8
        }
    }

    pub(in crate::runtime::engine) fn wsabuf_stride(&self) -> u64 {
        if self.arch.is_x86() {
            8
        } else {
            16
        }
    }

    pub(in crate::runtime::engine) fn read_wsabuf_descriptors(
        &self,
        address: u64,
        count: usize,
    ) -> Result<Vec<(u64, usize)>, VmError> {
        if address == 0 || count == 0 {
            return Ok(Vec::new());
        }
        let stride = self.wsabuf_stride();
        let pointer_offset = self.wsabuf_pointer_offset();
        let mut descriptors = Vec::with_capacity(count);
        for index in 0..count {
            let entry = address + index as u64 * stride;
            let length = self.read_u32(entry)? as usize;
            let buffer = self.read_pointer_value(entry + pointer_offset)?;
            descriptors.push((buffer, length));
        }
        Ok(descriptors)
    }

    pub(in crate::runtime::engine) fn read_wsabuf_payload(
        &self,
        address: u64,
        count: usize,
    ) -> Result<Vec<u8>, VmError> {
        let descriptors = self.read_wsabuf_descriptors(address, count)?;
        let mut payload = Vec::new();
        for (buffer, length) in descriptors {
            if buffer == 0 || length == 0 {
                continue;
            }
            payload.extend_from_slice(&self.read_bytes_from_memory(buffer, length)?);
        }
        Ok(payload)
    }

    pub(in crate::runtime::engine) fn write_wsabuf_payload(
        &mut self,
        address: u64,
        count: usize,
        data: &[u8],
    ) -> Result<usize, VmError> {
        if address == 0 || count == 0 || data.is_empty() {
            return Ok(0);
        }
        let descriptors = self.read_wsabuf_descriptors(address, count)?;
        let mut written = 0usize;
        for (buffer, length) in descriptors {
            if written >= data.len() {
                break;
            }
            if buffer == 0 || length == 0 {
                continue;
            }
            let chunk_len = length.min(data.len() - written);
            self.modules
                .memory_mut()
                .write(buffer, &data[written..written + chunk_len])?;
            written += chunk_len;
        }
        Ok(written)
    }

    pub(in crate::runtime::engine) fn create_protoent(
        &mut self,
        name: &str,
        protocol: i32,
    ) -> Result<u64, VmError> {
        let ptr_size = self.arch.pointer_size as u64;
        let name_bytes = format!("{name}\0").into_bytes();
        let name_ptr = self.alloc_process_heap_block(name_bytes.len() as u64, "protoent:name")?;
        let aliases_ptr = self.alloc_process_heap_block(ptr_size, "protoent:aliases")?;
        self.modules.memory_mut().write(name_ptr, &name_bytes)?;
        self.modules
            .memory_mut()
            .write(aliases_ptr, &vec![0u8; ptr_size as usize])?;

        let struct_size = if self.arch.is_x86() { 12 } else { 24 };
        let protoent_ptr = self.alloc_process_heap_block(struct_size, "protoent:struct")?;
        self.modules
            .memory_mut()
            .write(protoent_ptr, &vec![0u8; struct_size as usize])?;
        if self.arch.is_x86() {
            self.write_pointer_value(protoent_ptr, name_ptr)?;
            self.write_pointer_value(protoent_ptr + 4, aliases_ptr)?;
            self.write_u32(protoent_ptr + 8, protocol as u32)?;
        } else {
            self.write_pointer_value(protoent_ptr, name_ptr)?;
            self.write_pointer_value(protoent_ptr + 8, aliases_ptr)?;
            self.write_u32(protoent_ptr + 16, protocol as u32)?;
        }
        Ok(protoent_ptr)
    }

    pub(in crate::runtime::engine) fn create_servent(
        &mut self,
        name: &str,
        protocol: &str,
        port: u16,
    ) -> Result<u64, VmError> {
        let ptr_size = self.arch.pointer_size as u64;
        let name_bytes = format!("{name}\0").into_bytes();
        let protocol_bytes = format!("{protocol}\0").into_bytes();
        let name_ptr = self.alloc_process_heap_block(name_bytes.len() as u64, "servent:name")?;
        let aliases_ptr = self.alloc_process_heap_block(ptr_size, "servent:aliases")?;
        let protocol_ptr =
            self.alloc_process_heap_block(protocol_bytes.len() as u64, "servent:proto")?;
        self.modules.memory_mut().write(name_ptr, &name_bytes)?;
        self.modules
            .memory_mut()
            .write(aliases_ptr, &vec![0u8; ptr_size as usize])?;
        self.modules
            .memory_mut()
            .write(protocol_ptr, &protocol_bytes)?;

        let struct_size = if self.arch.is_x86() { 16 } else { 32 };
        let servent_ptr = self.alloc_process_heap_block(struct_size, "servent:struct")?;
        self.modules
            .memory_mut()
            .write(servent_ptr, &vec![0u8; struct_size as usize])?;
        if self.arch.is_x86() {
            self.write_pointer_value(servent_ptr, name_ptr)?;
            self.write_pointer_value(servent_ptr + 4, aliases_ptr)?;
            self.write_u16(servent_ptr + 8, port.to_be())?;
            self.write_pointer_value(servent_ptr + 12, protocol_ptr)?;
        } else {
            self.write_pointer_value(servent_ptr, name_ptr)?;
            self.write_pointer_value(servent_ptr + 8, aliases_ptr)?;
            self.write_u16(servent_ptr + 16, port.to_be())?;
            self.write_pointer_value(servent_ptr + 24, protocol_ptr)?;
        }
        Ok(servent_ptr)
    }

    pub(in crate::runtime::engine) fn safe_array_descriptor_size(&self) -> u64 {
        if self.arch.is_x86() {
            24
        } else {
            32
        }
    }

    pub(in crate::runtime::engine) fn safe_array_bounds_offset(&self) -> u64 {
        if self.arch.is_x86() {
            16
        } else {
            24
        }
    }

    pub(in crate::runtime::engine) fn safe_array_data_offset(&self) -> u64 {
        if self.arch.is_x86() {
            12
        } else {
            16
        }
    }

    pub(in crate::runtime::engine) fn safe_array_element_size(&self, vartype: u16) -> u32 {
        match vartype {
            2 | 11 | 18 => 2,
            3 | 4 | 10 | 19 | 22 | 23 => 4,
            5 | 6 | 7 | 14 | 20 | 21 => 8,
            16 | 17 => 1,
            _ => self.arch.pointer_size as u32,
        }
    }

    pub(in crate::runtime::engine) fn create_safe_array(
        &mut self,
        vartype: u16,
        count: u32,
        lower_bound: i32,
        source: &str,
    ) -> Result<u64, VmError> {
        let cb_elements = self.safe_array_element_size(vartype).max(1);
        let data_size = (count as u64).saturating_mul(cb_elements as u64).max(1);
        let data = self.alloc_process_heap_block(data_size, &format!("{source}:data"))?;
        self.modules
            .memory_mut()
            .write(data, &vec![0u8; data_size as usize])?;

        let descriptor_size = self.safe_array_descriptor_size();
        let descriptor = self.alloc_process_heap_block(descriptor_size, source)?;
        self.modules
            .memory_mut()
            .write(descriptor, &vec![0u8; descriptor_size as usize])?;
        self.write_u16(descriptor, 1)?;
        self.write_u16(descriptor + 2, 0)?;
        self.write_u32(descriptor + 4, cb_elements)?;
        self.write_u32(descriptor + 8, 0)?;
        self.write_pointer_value(descriptor + self.safe_array_data_offset(), data)?;
        let bounds = descriptor + self.safe_array_bounds_offset();
        self.write_u32(bounds, count)?;
        self.write_u32(bounds + 4, lower_bound as u32)?;
        Ok(descriptor)
    }

    pub(in crate::runtime::engine) fn read_safe_array_info(
        &self,
        array: u64,
    ) -> Result<(u64, u32, i32, u32, u16), VmError> {
        if array == 0 {
            return Ok((0, 0, 0, 0, 0));
        }
        let dims = self.read_u16(array)?;
        let cb_elements = self.read_u32(array + 4)?;
        let data = self.read_pointer_value(array + self.safe_array_data_offset())?;
        let bounds = array + self.safe_array_bounds_offset();
        let count = self.read_u32(bounds)?;
        let lower_bound = self.read_u32(bounds + 4)? as i32;
        Ok((data, cb_elements, lower_bound, count, dims))
    }

    pub(in crate::runtime::engine) fn allocate_global_atom(&mut self, name: &str) -> u16 {
        let trimmed = name.trim();
        if let Some((&atom, _)) = self
            .global_atoms
            .iter()
            .find(|(_, value)| value.eq_ignore_ascii_case(trimmed))
        {
            return atom;
        }
        let atom = self.next_atom.max(0xC000);
        self.next_atom = self.next_atom.saturating_add(1);
        self.global_atoms.insert(atom, trimmed.to_string());
        atom
    }

    pub(in crate::runtime::engine) fn find_global_atom(&self, name: &str) -> u16 {
        self.global_atoms
            .iter()
            .find(|(_, value)| value.eq_ignore_ascii_case(name.trim()))
            .map(|(&atom, _)| atom)
            .unwrap_or(0)
    }

    pub(in crate::runtime::engine) fn page_protect_from_perms(perms: u32) -> u32 {
        match perms & (PROT_READ | PROT_WRITE | PROT_EXEC) {
            bits if bits & PROT_EXEC != 0 && bits & PROT_WRITE != 0 => PAGE_EXECUTE_READWRITE,
            bits if bits & PROT_EXEC != 0 && bits & PROT_READ != 0 => PAGE_EXECUTE_READ,
            bits if bits & PROT_EXEC != 0 => PAGE_EXECUTE,
            bits if bits & PROT_WRITE != 0 => PAGE_READWRITE,
            bits if bits & PROT_READ != 0 => PAGE_READONLY,
            _ => PAGE_NOACCESS,
        }
    }

    pub(in crate::runtime::engine) fn civil_from_days(days: i64) -> (u16, u16, u16) {
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = mp + if mp < 10 { 3 } else { -9 };
        let year = y + if month <= 2 { 1 } else { 0 };
        (year as u16, month as u16, day as u16)
    }

    pub(in crate::runtime::engine) fn system_time_components_from_filetime(
        filetime: u64,
    ) -> (u16, u16, u16, u16, u16, u16, u16, u16) {
        let unix_100ns = filetime.saturating_sub(WINDOWS_TO_UNIX_EPOCH_100NS);
        let total_seconds = (unix_100ns / 10_000_000) as i64;
        let milliseconds = ((unix_100ns % 10_000_000) / 10_000) as u16;
        let days = total_seconds.div_euclid(86_400);
        let seconds_of_day = total_seconds.rem_euclid(86_400) as u32;
        let (year, month, day) = Self::civil_from_days(days);
        let weekday = (days + 4).rem_euclid(7) as u16;
        let hour = (seconds_of_day / 3_600) as u16;
        let minute = ((seconds_of_day % 3_600) / 60) as u16;
        let second = (seconds_of_day % 60) as u16;
        (
            year,
            month,
            weekday,
            day,
            hour,
            minute,
            second,
            milliseconds,
        )
    }

    pub(in crate::runtime::engine) fn write_systemtime_struct(
        &mut self,
        address: u64,
        components: (u16, u16, u16, u16, u16, u16, u16, u16),
    ) -> Result<(), VmError> {
        if address == 0 {
            return Ok(());
        }
        let (year, month, weekday, day, hour, minute, second, milliseconds) = components;
        let mut payload = Vec::with_capacity(16);
        for value in [
            year,
            month,
            weekday,
            day,
            hour,
            minute,
            second,
            milliseconds,
        ] {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        self.modules.memory_mut().write(address, &payload)?;
        Ok(())
    }

    pub(in crate::runtime::engine) fn next_guid_bytes_le(&mut self, version: u16) -> [u8; 16] {
        let time_low = self.guid_rng.next_u32();
        let time_mid = self.guid_rng.next_u32() as u16;
        let time_hi_and_version = (self.guid_rng.next_u32() as u16 & 0x0FFF) | (version << 12);
        let clock_seq_hi_and_reserved = (self.guid_rng.next_u32() as u8 & 0x3F) | 0x80;
        let clock_seq_low = self.guid_rng.next_u32() as u8;
        let mut node = [0u8; 6];
        self.guid_rng.fill_bytes(&mut node);

        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&time_low.to_le_bytes());
        bytes[4..6].copy_from_slice(&time_mid.to_le_bytes());
        bytes[6..8].copy_from_slice(&time_hi_and_version.to_le_bytes());
        bytes[8] = clock_seq_hi_and_reserved;
        bytes[9] = clock_seq_low;
        bytes[10..16].copy_from_slice(&node);
        bytes
    }

    pub(in crate::runtime::engine) fn read_guid_bytes_le_or_zero(
        &self,
        address: u64,
    ) -> Result<[u8; 16], VmError> {
        if address == 0 {
            return Ok([0; 16]);
        }
        let bytes = self.read_bytes_from_memory(address, 16)?;
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&bytes);
        Ok(guid)
    }

    pub(in crate::runtime::engine) fn format_guid_bytes_le(bytes: &[u8; 16]) -> String {
        let time_low = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let time_mid = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        let time_hi_and_version = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        format!(
            "{{{time_low:08X}-{time_mid:04X}-{time_hi_and_version:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        )
    }

    pub(in crate::runtime::engine) fn write_startup_info(
        &mut self,
        address: u64,
    ) -> Result<(), VmError> {
        if address == 0 {
            return Ok(());
        }
        let size = if self.arch.is_x86() {
            STARTUPINFO_SIZE_X86
        } else {
            STARTUPINFO_SIZE_X64
        };
        let mut bytes = vec![0u8; size as usize];
        bytes[0..4].copy_from_slice(&size.to_le_bytes());
        self.modules.memory_mut().write(address, &bytes)?;
        Ok(())
    }

    pub(in crate::runtime::engine) fn write_thread_context(
        &mut self,
        thread_handle: u32,
        address: u64,
    ) -> Result<bool, VmError> {
        let Some(tid) = self.scheduler.thread_tid_for_handle(thread_handle) else {
            return Ok(false);
        };
        let Some(registers) = self
            .scheduler
            .thread_snapshot(tid)
            .map(|thread| thread.registers)
        else {
            return Ok(false);
        };
        serialize_register_context(self.modules.memory_mut(), self.arch, address, &registers)?;
        Ok(true)
    }

    pub(in crate::runtime::engine) fn read_thread_context(
        &mut self,
        thread_handle: u32,
        address: u64,
    ) -> Result<bool, VmError> {
        let Some(tid) = self.scheduler.thread_tid_for_handle(thread_handle) else {
            return Ok(false);
        };
        let registers = deserialize_register_context(self.modules.memory(), self.arch, address)?;
        self.scheduler
            .set_thread_registers(tid, registers)
            .ok_or(VmError::RuntimeInvariant(
                "failed to store thread register context",
            ))?;
        Ok(true)
    }

    pub(in crate::runtime::engine) fn copy_memory_block(
        &mut self,
        destination: u64,
        source: u64,
        size: usize,
    ) -> Result<u64, VmError> {
        if destination != 0 && source != 0 && size != 0 {
            let bytes = self.read_bytes_from_memory(source, size)?;
            self.modules.memory_mut().write(destination, &bytes)?;
        }
        Ok(destination)
    }

    pub(in crate::runtime::engine) fn fill_memory_pattern(
        &mut self,
        address: u64,
        length: u64,
        value: u8,
    ) -> Result<(), VmError> {
        if address == 0 || length == 0 {
            return Ok(());
        }

        let chunk = vec![value; 0x1000];
        let mut offset = 0u64;
        while offset < length {
            let writable = ((length - offset) as usize).min(chunk.len());
            self.modules
                .memory_mut()
                .write(address + offset, &chunk[..writable])?;
            offset += writable as u64;
        }
        Ok(())
    }

    pub(in crate::runtime::engine) fn is_writable_guest_range(
        &self,
        address: u64,
        size: u64,
    ) -> bool {
        if address == 0 || size == 0 {
            return false;
        }
        self.modules
            .memory()
            .find_region(address, size)
            .map(|region| region.perms & PROT_WRITE != 0)
            .unwrap_or(false)
    }
}
