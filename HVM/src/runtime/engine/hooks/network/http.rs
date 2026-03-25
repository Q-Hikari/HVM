use super::*;

const INTERNET_SCHEME_UNKNOWN: u32 = u32::MAX;
const INTERNET_SCHEME_DEFAULT: u32 = 0;
const INTERNET_SCHEME_FTP: u32 = 1;
const INTERNET_SCHEME_HTTP: u32 = 3;
const INTERNET_SCHEME_HTTPS: u32 = 4;
const INTERNET_SCHEME_FILE: u32 = 5;

#[derive(Debug, Clone, Default)]
struct UrlComponentView {
    text: String,
    char_offset: usize,
}

#[derive(Debug, Clone, Default)]
struct ParsedInternetUrl {
    scheme: UrlComponentView,
    host: UrlComponentView,
    username: UrlComponentView,
    password: UrlComponentView,
    path: UrlComponentView,
    extra: UrlComponentView,
    port: u16,
    scheme_id: u32,
}

#[derive(Debug, Clone, Copy)]
struct UrlComponentsLayout {
    scheme_ptr: u64,
    scheme_len: u64,
    scheme_id: u64,
    host_ptr: u64,
    host_len: u64,
    port: u64,
    user_ptr: u64,
    user_len: u64,
    password_ptr: u64,
    password_len: u64,
    path_ptr: u64,
    path_len: u64,
    extra_ptr: u64,
    extra_len: u64,
}

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn merge_http_headers(
        existing: &str,
        additional: &str,
    ) -> String {
        match (existing.is_empty(), additional.is_empty()) {
            (_, true) => existing.to_string(),
            (true, false) => additional.to_string(),
            (false, false) => format!("{existing}\r\n{additional}"),
        }
    }

    fn url_components_layout(&self) -> UrlComponentsLayout {
        if self.arch.is_x86() {
            UrlComponentsLayout {
                scheme_ptr: 4,
                scheme_len: 8,
                scheme_id: 12,
                host_ptr: 16,
                host_len: 20,
                port: 24,
                user_ptr: 28,
                user_len: 32,
                password_ptr: 36,
                password_len: 40,
                path_ptr: 44,
                path_len: 48,
                extra_ptr: 52,
                extra_len: 56,
            }
        } else {
            UrlComponentsLayout {
                scheme_ptr: 8,
                scheme_len: 16,
                scheme_id: 20,
                host_ptr: 24,
                host_len: 32,
                port: 36,
                user_ptr: 40,
                user_len: 48,
                password_ptr: 56,
                password_len: 64,
                path_ptr: 72,
                path_len: 80,
                extra_ptr: 88,
                extra_len: 96,
            }
        }
    }

    pub(in crate::runtime::engine) fn internet_scheme_details(scheme: &str) -> (u32, u16) {
        match scheme.to_ascii_lowercase().as_str() {
            "http" => (INTERNET_SCHEME_HTTP, 80),
            "https" => (INTERNET_SCHEME_HTTPS, 443),
            "ftp" => (INTERNET_SCHEME_FTP, 21),
            "file" => (INTERNET_SCHEME_FILE, 0),
            "" => (INTERNET_SCHEME_DEFAULT, 0),
            _ => (INTERNET_SCHEME_UNKNOWN, 0),
        }
    }

    pub(in crate::runtime::engine) fn char_offset_for_byte_index(
        text: &str,
        byte_index: usize,
    ) -> usize {
        text[..byte_index.min(text.len())].chars().count()
    }

    fn parse_internet_url(url: &str) -> ParsedInternetUrl {
        let mut parsed = ParsedInternetUrl::default();
        let trimmed = url.trim();

        let (scheme_text, default_port, scheme_end) = if let Some(index) = trimmed.find("://") {
            let scheme = trimmed[..index].to_string();
            let (scheme_id, port) = Self::internet_scheme_details(&scheme);
            parsed.scheme_id = scheme_id;
            (scheme, port, index + 3)
        } else if let Some(index) = trimmed.find(':') {
            let candidate = &trimmed[..index];
            if !candidate.is_empty()
                && candidate
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
            {
                let scheme = candidate.to_string();
                let (scheme_id, port) = Self::internet_scheme_details(&scheme);
                parsed.scheme_id = scheme_id;
                (scheme, port, index + 1)
            } else {
                parsed.scheme_id = INTERNET_SCHEME_UNKNOWN;
                (String::new(), 0, 0)
            }
        } else {
            parsed.scheme_id = INTERNET_SCHEME_UNKNOWN;
            (String::new(), 0, 0)
        };
        parsed.scheme = UrlComponentView {
            text: scheme_text,
            char_offset: 0,
        };

        let authority_end = trimmed[scheme_end..]
            .find(['/', '?', '#'])
            .map(|offset| scheme_end + offset)
            .unwrap_or(trimmed.len());
        let authority = &trimmed[scheme_end..authority_end];
        let (userinfo, host_port) = authority.rsplit_once('@').unwrap_or(("", authority));
        if !userinfo.is_empty() {
            let userinfo_offset = scheme_end;
            if let Some((username, password)) = userinfo.split_once(':') {
                parsed.username = UrlComponentView {
                    text: username.to_string(),
                    char_offset: Self::char_offset_for_byte_index(trimmed, userinfo_offset),
                };
                parsed.password = UrlComponentView {
                    text: password.to_string(),
                    char_offset: Self::char_offset_for_byte_index(
                        trimmed,
                        userinfo_offset + username.len() + 1,
                    ),
                };
            } else {
                parsed.username = UrlComponentView {
                    text: userinfo.to_string(),
                    char_offset: Self::char_offset_for_byte_index(trimmed, userinfo_offset),
                };
            }
        }

        let host_offset_bytes = authority_end.saturating_sub(host_port.len());
        let (host_text, port) = if let Some(rest) = host_port.strip_prefix('[') {
            if let Some(end_bracket) = rest.find(']') {
                let host = rest[..end_bracket].to_string();
                let port = rest[end_bracket + 1..]
                    .strip_prefix(':')
                    .and_then(|value| value.parse::<u16>().ok())
                    .unwrap_or(default_port);
                (host, port)
            } else {
                (host_port.to_string(), default_port)
            }
        } else if let Some((host, port_text)) = host_port.rsplit_once(':') {
            if host_port.matches(':').count() == 1 {
                (
                    host.to_string(),
                    port_text.parse::<u16>().unwrap_or(default_port),
                )
            } else {
                (host_port.to_string(), default_port)
            }
        } else {
            (host_port.to_string(), default_port)
        };
        parsed.host = UrlComponentView {
            text: host_text,
            char_offset: Self::char_offset_for_byte_index(trimmed, host_offset_bytes),
        };
        parsed.port = port;

        let extra_start = trimmed[authority_end..]
            .find(['?', '#'])
            .map(|offset| authority_end + offset)
            .unwrap_or(trimmed.len());
        if authority_end < extra_start {
            parsed.path = UrlComponentView {
                text: trimmed[authority_end..extra_start].to_string(),
                char_offset: Self::char_offset_for_byte_index(trimmed, authority_end),
            };
        }
        if extra_start < trimmed.len() {
            parsed.extra = UrlComponentView {
                text: trimmed[extra_start..].to_string(),
                char_offset: Self::char_offset_for_byte_index(trimmed, extra_start),
            };
        }

        parsed
    }

    pub(in crate::runtime::engine) fn read_internet_url_input(
        &self,
        address: u64,
        length: u64,
        wide: bool,
    ) -> Result<String, VmError> {
        if wide {
            if length == 0 {
                self.read_wide_string_from_memory(address)
            } else {
                self.read_wide_counted_string_from_memory(address, length as usize)
            }
        } else if length == 0 {
            self.read_c_string_from_memory(address)
        } else {
            Ok(Self::decode_ascii_bytes_ignoring_errors(
                &self.read_bytes_from_memory(address, length as usize)?,
            ))
        }
    }

    pub(in crate::runtime::engine) fn canonicalize_internet_url(url: &str) -> String {
        url.trim().replace('\\', "/")
    }

    fn write_url_component_output(
        &mut self,
        components_ptr: u64,
        pointer_offset: u64,
        length_offset: u64,
        source_ptr: u64,
        component: &UrlComponentView,
        wide: bool,
    ) -> Result<(), VmError> {
        let field_ptr = components_ptr + pointer_offset;
        let field_len = components_ptr + length_offset;
        let buffer_ptr = self.read_pointer_value(field_ptr).unwrap_or(0);
        let requested_len = self.read_u32(field_len).unwrap_or(0) as usize;
        let actual_len = if wide {
            component.text.encode_utf16().count()
        } else {
            component.text.len()
        };

        if actual_len == 0 {
            self.write_pointer_value(field_ptr, 0)?;
            self.write_u32(field_len, 0)?;
            return Ok(());
        }

        if buffer_ptr != 0 && requested_len > actual_len {
            if wide {
                let _ =
                    self.write_wide_string_to_memory(buffer_ptr, requested_len, &component.text)?;
            } else {
                let _ =
                    self.write_c_string_to_memory(buffer_ptr, requested_len, &component.text)?;
            }
            self.write_pointer_value(field_ptr, buffer_ptr)?;
        } else {
            let stride = if wide { 2 } else { 1 };
            self.write_pointer_value(
                field_ptr,
                source_ptr + (component.char_offset * stride) as u64,
            )?;
        }
        self.write_u32(field_len, actual_len as u32)?;
        Ok(())
    }

    pub(in crate::runtime::engine) fn internet_canonicalize_url(
        &mut self,
        wide: bool,
        source_ptr: u64,
        destination_ptr: u64,
        length_ptr: u64,
    ) -> Result<u64, VmError> {
        if source_ptr == 0 || length_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }

        let url = self.read_internet_url_input(source_ptr, 0, wide)?;
        let canonical = Self::canonicalize_internet_url(&url);
        let capacity = self.read_u32(length_ptr)? as usize;
        let required = if wide {
            canonical.encode_utf16().count()
        } else {
            canonical.len()
        };
        self.write_u32(length_ptr, required as u32)?;
        if destination_ptr == 0 || capacity <= required {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }

        if wide {
            let _ = self.write_wide_string_to_memory(destination_ptr, capacity, &canonical)?;
        } else {
            let _ = self.write_c_string_to_memory(destination_ptr, capacity, &canonical)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn internet_crack_url(
        &mut self,
        wide: bool,
        source_ptr: u64,
        length: u64,
        components_ptr: u64,
    ) -> Result<u64, VmError> {
        if source_ptr == 0 || components_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }

        let url = self.read_internet_url_input(source_ptr, length, wide)?;
        let parsed = Self::parse_internet_url(&url);
        let layout = self.url_components_layout();

        self.write_url_component_output(
            components_ptr,
            layout.scheme_ptr,
            layout.scheme_len,
            source_ptr,
            &parsed.scheme,
            wide,
        )?;
        self.write_u32(components_ptr + layout.scheme_id, parsed.scheme_id)?;
        self.write_url_component_output(
            components_ptr,
            layout.host_ptr,
            layout.host_len,
            source_ptr,
            &parsed.host,
            wide,
        )?;
        self.write_u16(components_ptr + layout.port, parsed.port)?;
        self.write_url_component_output(
            components_ptr,
            layout.user_ptr,
            layout.user_len,
            source_ptr,
            &parsed.username,
            wide,
        )?;
        self.write_url_component_output(
            components_ptr,
            layout.password_ptr,
            layout.password_len,
            source_ptr,
            &parsed.password,
            wide,
        )?;
        self.write_url_component_output(
            components_ptr,
            layout.path_ptr,
            layout.path_len,
            source_ptr,
            &parsed.path,
            wide,
        )?;
        self.write_url_component_output(
            components_ptr,
            layout.extra_ptr,
            layout.extra_len,
            source_ptr,
            &parsed.extra,
            wide,
        )?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn winhttp_query_response_value(
        &self,
        handle: u32,
        info_level: u32,
    ) -> Option<Vec<u8>> {
        let request = self.network.get_request(handle)?;
        let query = info_level & 0xFFFF;
        if info_level & WINHTTP_QUERY_FLAG_NUMBER != 0 {
            let numeric = match query {
                WINHTTP_QUERY_STATUS_CODE => request.status_code as u32,
                WINHTTP_QUERY_CONTENT_LENGTH => {
                    request.response_body.len().min(u32::MAX as usize) as u32
                }
                _ => request.status_code as u32,
            };
            return Some(numeric.to_le_bytes().to_vec());
        }

        let text = match query {
            WINHTTP_QUERY_STATUS_CODE => request.status_code.to_string(),
            WINHTTP_QUERY_STATUS_TEXT => {
                if request.status_code == 200 {
                    "OK".to_string()
                } else {
                    "STATUS".to_string()
                }
            }
            WINHTTP_QUERY_CONTENT_LENGTH => request.response_body.len().to_string(),
            WINHTTP_QUERY_RAW_HEADERS_CRLF => {
                String::from_utf8_lossy(&request.response_headers).into_owned()
            }
            _ => String::from_utf8_lossy(&request.response_headers).into_owned(),
        };
        let mut encoded = text
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        encoded.extend_from_slice(&[0, 0]);
        Some(encoded)
    }

    pub(in crate::runtime::engine) fn apply_configured_http_response(
        &mut self,
        handle: u32,
    ) -> Result<(), VmError> {
        let Some((host, path, verb)) = self.network.request_route(handle) else {
            return Ok(());
        };
        let Some((rule_index, rule)) = self
            .config
            .http_response_rule_with_index_for(&host, &path, &verb)
        else {
            return Ok(());
        };
        let match_count = self
            .http_response_rule_hits
            .get(&rule_index)
            .copied()
            .unwrap_or(0);
        let response_index = (match_count as usize).min(rule.responses.len().saturating_sub(1));
        let response = rule.responses[response_index].clone();
        self.http_response_rule_hits
            .insert(rule_index, match_count.saturating_add(1));
        let status_code = response.status_code;
        let body = response.body;
        let response_headers =
            Self::build_http_response_headers(status_code, &response.headers, body.len());
        let body_len = body.len();
        let _ = self.network.with_request_mut(handle, move |request| {
            request.status_code = status_code;
            request.response_body = body;
            request.response_headers = response_headers;
            request.read_offset = 0;
        });
        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(handle));
        fields.insert("host".to_string(), json!(host));
        fields.insert("path".to_string(), json!(path));
        fields.insert("verb".to_string(), json!(verb));
        fields.insert("rule_index".to_string(), json!(rule_index));
        fields.insert("match_count".to_string(), json!(match_count));
        fields.insert("response_index".to_string(), json!(response_index));
        fields.insert("status_code".to_string(), json!(status_code));
        fields.insert("body_len".to_string(), json!(body_len));
        self.log_runtime_event("HTTP_RESPONSE_RULE", fields)
    }

    pub(in crate::runtime::engine) fn build_http_response_headers(
        status_code: u32,
        headers: &[HttpResponseHeader],
        body_len: usize,
    ) -> Vec<u8> {
        let mut text = format!(
            "HTTP/1.1 {status_code} {}\r\n",
            Self::http_status_text(status_code)
        );
        let mut has_content_length = false;
        for header in headers {
            if header.name.eq_ignore_ascii_case("Content-Length") {
                has_content_length = true;
            }
            text.push_str(&header.name);
            text.push_str(": ");
            text.push_str(&header.value);
            text.push_str("\r\n");
        }
        if !has_content_length {
            text.push_str(&format!("Content-Length: {body_len}\r\n"));
        }
        text.push_str("\r\n");
        text.into_bytes()
    }

    pub(in crate::runtime::engine) fn http_status_text(status_code: u32) -> &'static str {
        match status_code {
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Status",
        }
    }
}
