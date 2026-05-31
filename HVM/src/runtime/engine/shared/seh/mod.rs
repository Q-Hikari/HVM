use super::*;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const EXCEPTION_CONTINUE_EXECUTION: u32 = 0;
const EXCEPTION_CONTINUE_SEARCH: u32 = 1;
const X86_EXCEPTION_CHAIN_END: u64 = u32::MAX as u64;
const X86_EXCEPTION_RECORD_SIZE: usize = 0x50;
const X86_CONTEXT_SIZE: usize = 0x2CC;
const X86_CONTEXT_FULL: u32 = 0x0001_0007;
const X86_CONTEXT_SEG_GS_OFFSET: u64 = 0x8C;
const X86_CONTEXT_SEG_FS_OFFSET: u64 = 0x90;
const X86_CONTEXT_SEG_ES_OFFSET: u64 = 0x94;
const X86_CONTEXT_SEG_DS_OFFSET: u64 = 0x98;
const X86_CONTEXT_SEG_CS_OFFSET: u64 = 0xBC;
const X86_CONTEXT_SEG_SS_OFFSET: u64 = 0xC8;
const X86_EXCEPTION_DISPATCH_STACK: u64 = 0x400;
const X64_EXCEPTION_RECORD_SIZE: usize = 0x98;
const X64_CONTEXT_SIZE: usize = 0x200;
const X64_CONTEXT_FLAGS_OFFSET: u64 = 0x30;
const X64_CONTEXT_FULL: u32 = 0x0010_000B;
const X64_DISPATCHER_CONTEXT_SIZE: usize = 0x50;
const X64_EXCEPTION_POINTERS_SIZE: usize = 0x10;
const X64_EXCEPTION_DISPATCH_STACK: u64 = 0x2000;
const X64_NULL_PC_CONTINUATION_SCAN_WINDOW: u64 = 0x2000;
const X64_TOP_LEVEL_EXCEPTION_FILTER_REASON: u64 = 2;
const X64_UNW_FLAG_EHANDLER: u8 = 0x1;
const X64_UNW_FLAG_UHANDLER: u8 = 0x2;
const X64_UNW_FLAG_CHAININFO: u8 = 0x4;
const X64_UWOP_PUSH_NONVOL: u8 = 0;
const X64_UWOP_ALLOC_LARGE: u8 = 1;
const X64_UWOP_ALLOC_SMALL: u8 = 2;
const X64_UWOP_SET_FPREG: u8 = 3;
const X64_UWOP_SAVE_NONVOL: u8 = 4;
const X64_UWOP_SAVE_NONVOL_FAR: u8 = 5;
const X64_UWOP_SAVE_XMM128: u8 = 8;
const X64_UWOP_SAVE_XMM128_FAR: u8 = 9;
const X64_UWOP_PUSH_MACHFRAME: u8 = 10;
const STARTUP_CONTEXT_RECORD_SIZE_X86: u64 = 0x200;
const STARTUP_CONTEXT_RECORD_SIZE_X64: u64 = 0x200;
const STARTUP_NTCONTINUE_RESUME_COUNT: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct X64RuntimeFunction {
    entry_address: u64,
    begin_rva: u32,
    end_rva: u32,
    unwind_rva: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum X64UnwindOperation {
    PushNonVol {
        register: u8,
    },
    AllocLarge {
        size: u32,
    },
    AllocSmall {
        size: u32,
    },
    SetFpReg,
    SaveNonVol {
        register: u8,
        offset: u32,
    },
    SaveNonVolFar {
        register: u8,
        offset: u32,
    },
    SaveXmm128 {
        register: u8,
        offset: u32,
    },
    SaveXmm128Far {
        register: u8,
        offset: u32,
    },
    PushMachFrame {
        with_error_code: bool,
    },
    /// Unknown or unsupported unwind code — treated as a no-op during unwinding.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct X64UnwindCode {
    code_offset: u8,
    operation: X64UnwindOperation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct X64UnwindInfo {
    flags: u8,
    prolog_size: u8,
    frame_register: u8,
    frame_offset: u8,
    unwind_info_address: u64,
    handler_address: Option<u64>,
    handler_data_address: Option<u64>,
    operations: Vec<X64UnwindCode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::runtime::engine) struct X64RuntimeFunctionLookup {
    pub(in crate::runtime::engine) image_base: u64,
    pub(in crate::runtime::engine) function_entry_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct X64VirtualUnwindResult {
    image_base: u64,
    function_entry_address: u64,
    unwind_info_address: u64,
    establisher_frame: u64,
    handler_address: Option<u64>,
    handler_data_address: Option<u64>,
    flags: u8,
    leaf: bool,
    caller_context: RegisterFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct X64ScopeRecord {
    begin_rva: u32,
    end_rva: u32,
    handler_rva: u32,
    jump_target: u32,
}

fn align_up_u64(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return value;
    }
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
        .unwrap_or(value)
}

fn x64_register_name(register: u8) -> Option<&'static str> {
    match register {
        0 => Some("rax"),
        1 => Some("rcx"),
        2 => Some("rdx"),
        3 => Some("rbx"),
        4 => Some("rsp"),
        5 => Some("rbp"),
        6 => Some("rsi"),
        7 => Some("rdi"),
        8 => Some("r8"),
        9 => Some("r9"),
        10 => Some("r10"),
        11 => Some("r11"),
        12 => Some("r12"),
        13 => Some("r13"),
        14 => Some("r14"),
        15 => Some("r15"),
        _ => None,
    }
}

mod seh_dispatch;
mod seh_unwind;
