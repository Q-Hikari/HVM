use super::*;

use std::net::Ipv4Addr;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn resolve_ipv4_like_winsock(
        &self,
        value: &str,
    ) -> Option<Ipv4Addr> {
        parse_ipv4_like_winsock(value)
    }

    pub(in crate::runtime::engine) fn synthetic_host_ipv4(&self, value: &str) -> Ipv4Addr {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("localhost") {
            Ipv4Addr::LOCALHOST
        } else {
            self.resolve_ipv4_like_winsock(trimmed)
                .unwrap_or(Ipv4Addr::LOCALHOST)
        }
    }

    pub(in crate::runtime::engine) fn synthetic_host_ipv4_text(&self, value: &str) -> String {
        self.synthetic_host_ipv4(value).to_string()
    }
}

fn parse_ipv4_like_winsock(value: &str) -> Option<Ipv4Addr> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let components = trimmed
        .split('.')
        .map(parse_ipv4_component)
        .collect::<Option<Vec<_>>>()?;

    let packed = match components.as_slice() {
        [single] => *single,
        [a, b] if *a <= 0xff && *b <= 0x00ff_ffff => (*a << 24) | *b,
        [a, b, c] if *a <= 0xff && *b <= 0xff && *c <= 0xffff => (*a << 24) | (*b << 16) | *c,
        [a, b, c, d] if *a <= 0xff && *b <= 0xff && *c <= 0xff && *d <= 0xff => {
            (*a << 24) | (*b << 16) | (*c << 8) | *d
        }
        _ => return None,
    };

    Some(Ipv4Addr::from(packed.to_be_bytes()))
}

fn parse_ipv4_component(component: &str) -> Option<u32> {
    if component.is_empty() {
        return None;
    }

    let (digits, radix) = if let Some(hex) = component
        .strip_prefix("0x")
        .or_else(|| component.strip_prefix("0X"))
    {
        (hex, 16)
    } else if component.len() > 1 && component.starts_with('0') {
        (component, 8)
    } else {
        (component, 10)
    };

    if digits.is_empty() {
        return None;
    }

    u32::from_str_radix(digits, radix).ok()
}
