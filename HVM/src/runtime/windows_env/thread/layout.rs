use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::runtime::windows_env) struct TebOffsetGroup {
    pub exception_list: usize,
    pub stack_base: usize,
    pub stack_limit: usize,
    pub self_pointer: usize,
    pub client_id: usize,
    pub tls_pointer: usize,
    pub tls_slots: usize,
    pub peb: usize,
    pub last_error: usize,
}

pub(in crate::runtime::windows_env) fn teb_offsets_for_arch(
    arch: &'static ArchSpec,
) -> TebOffsetGroup {
    if arch.is_x86() {
        TebOffsetGroup {
            exception_list: 0x00,
            stack_base: 0x04,
            stack_limit: 0x08,
            self_pointer: 0x18,
            client_id: 0x20,
            tls_pointer: 0x2C,
            tls_slots: 0xE10,
            peb: 0x30,
            last_error: 0x34,
        }
    } else {
        TebOffsetGroup {
            exception_list: 0x00,
            stack_base: 0x08,
            stack_limit: 0x10,
            self_pointer: 0x30,
            client_id: 0x40,
            tls_pointer: 0x58,
            tls_slots: 0x1480,
            peb: 0x60,
            last_error: 0x68,
        }
    }
}
