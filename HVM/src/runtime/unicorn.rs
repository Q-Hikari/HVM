use std::ffi::{c_char, c_int, c_void, CStr};

pub const UC_ARCH_X86: c_int = 4;
pub const UC_MODE_32: c_int = 4;
pub const UC_MODE_64: c_int = 8;
pub const UC_PROT_READ: u32 = 1;
pub const UC_PROT_WRITE: u32 = 2;
pub const UC_PROT_EXEC: u32 = 4;
pub const UC_HOOK_MEM_READ_UNMAPPED: c_int = 1 << 4;
pub const UC_HOOK_MEM_WRITE_UNMAPPED: c_int = 1 << 5;
pub const UC_HOOK_MEM_FETCH_UNMAPPED: c_int = 1 << 6;
pub const UC_HOOK_MEM_READ_PROT: c_int = 1 << 7;
pub const UC_HOOK_MEM_WRITE_PROT: c_int = 1 << 8;
pub const UC_HOOK_MEM_FETCH_PROT: c_int = 1 << 9;
pub const UC_HOOK_CODE: c_int = 1 << 2;
pub const UC_HOOK_BLOCK: c_int = 1 << 3;
pub const UC_HOOK_MEM_WRITE: c_int = 1 << 11;
pub const UC_MEM_READ_UNMAPPED: c_int = 19;
pub const UC_MEM_WRITE_UNMAPPED: c_int = 20;
pub const UC_MEM_FETCH_UNMAPPED: c_int = 21;
pub const UC_MEM_WRITE_PROT: c_int = 22;
pub const UC_MEM_READ_PROT: c_int = 23;
pub const UC_MEM_FETCH_PROT: c_int = 24;
pub const UC_X86_REG_CS: c_int = 11;
pub const UC_X86_REG_DS: c_int = 17;
pub const UC_X86_REG_EAX: c_int = 19;
pub const UC_X86_REG_EBP: c_int = 20;
pub const UC_X86_REG_EBX: c_int = 21;
pub const UC_X86_REG_ECX: c_int = 22;
pub const UC_X86_REG_EDI: c_int = 23;
pub const UC_X86_REG_EDX: c_int = 24;
pub const UC_X86_REG_EFLAGS: c_int = 25;
pub const UC_X86_REG_EIP: c_int = 26;
pub const UC_X86_REG_ES: c_int = 28;
pub const UC_X86_REG_ESI: c_int = 29;
pub const UC_X86_REG_ESP: c_int = 30;
pub const UC_X86_REG_FS: c_int = 32;
pub const UC_X86_REG_GS: c_int = 33;
pub const UC_X86_REG_RAX: c_int = 35;
pub const UC_X86_REG_RBP: c_int = 36;
pub const UC_X86_REG_RBX: c_int = 37;
pub const UC_X86_REG_RCX: c_int = 38;
pub const UC_X86_REG_RDI: c_int = 39;
pub const UC_X86_REG_RDX: c_int = 40;
pub const UC_X86_REG_RIP: c_int = 41;
pub const UC_X86_REG_RSI: c_int = 43;
pub const UC_X86_REG_RSP: c_int = 44;
pub const UC_X86_REG_SS: c_int = 49;
pub const UC_X86_REG_R8: c_int = 106;
pub const UC_X86_REG_R9: c_int = 107;
pub const UC_X86_REG_R10: c_int = 108;
pub const UC_X86_REG_R11: c_int = 109;
pub const UC_X86_REG_R12: c_int = 110;
pub const UC_X86_REG_R13: c_int = 111;
pub const UC_X86_REG_R14: c_int = 112;
pub const UC_X86_REG_R15: c_int = 113;
pub const UC_X86_REG_GDTR: c_int = 243;
pub const UC_X86_REG_GS_BASE: c_int = 251;
pub const UC_X86_REG_RFLAGS: c_int = 253;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct X86Mmr {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub flags: u32,
}

pub type UcHook = usize;
pub type UcEngine = c_void;
pub type CodeHook = unsafe extern "C" fn(*mut UcEngine, u64, u32, *mut c_void);
pub type MemHook = unsafe extern "C" fn(*mut UcEngine, c_int, u64, c_int, i64, *mut c_void);
pub type MemProtHook =
    unsafe extern "C" fn(*mut UcEngine, c_int, u64, c_int, i64, *mut c_void) -> bool;

unsafe extern "C" {
    fn uc_open(arch: c_int, mode: c_int, out: *mut *mut UcEngine) -> c_int;
    fn uc_close(handle: *mut UcEngine) -> c_int;
    fn uc_mem_map(handle: *mut UcEngine, address: u64, size: u64, perms: u32) -> c_int;
    fn uc_mem_unmap(handle: *mut UcEngine, address: u64, size: u64) -> c_int;
    fn uc_mem_protect(handle: *mut UcEngine, address: u64, size: u64, perms: u32) -> c_int;
    fn uc_mem_write(handle: *mut UcEngine, address: u64, data: *const c_void, size: u64) -> c_int;
    fn uc_mem_read(handle: *mut UcEngine, address: u64, data: *mut c_void, size: u64) -> c_int;
    fn uc_reg_write(handle: *mut UcEngine, regid: c_int, value: *const c_void) -> c_int;
    fn uc_reg_read(handle: *mut UcEngine, regid: c_int, value: *mut c_void) -> c_int;
    fn uc_emu_start(
        handle: *mut UcEngine,
        begin: u64,
        until: u64,
        timeout: u64,
        count: usize,
    ) -> c_int;
    fn uc_emu_stop(handle: *mut UcEngine) -> c_int;
    fn uc_hook_add(
        handle: *mut UcEngine,
        hook: *mut UcHook,
        hook_type: c_int,
        callback: *mut c_void,
        user_data: *mut c_void,
        begin: u64,
        end: u64,
        ...
    ) -> c_int;
    fn uc_strerror(code: c_int) -> *const c_char;
}

pub struct UnicornApi {
    backend: &'static str,
}

impl std::fmt::Debug for UnicornApi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnicornApi")
            .field("backend", &self.backend)
            .finish()
    }
}

impl UnicornApi {
    pub fn load_default() -> Result<Self, String> {
        Ok(Self {
            backend: "bundled-static",
        })
    }

    pub fn open_x86(&self) -> Result<UnicornHandle<'_>, String> {
        let handle = self.open_x86_raw()?;
        Ok(UnicornHandle { api: self, handle })
    }

    pub fn open_x86_raw(&self) -> Result<*mut UcEngine, String> {
        self.open_raw(UC_MODE_32)
    }

    pub fn open_x64_raw(&self) -> Result<*mut UcEngine, String> {
        self.open_raw(UC_MODE_64)
    }

    fn open_raw(&self, mode: c_int) -> Result<*mut UcEngine, String> {
        let mut handle = std::ptr::null_mut();
        let err = unsafe { uc_open(UC_ARCH_X86, mode, &mut handle) };
        self.check_error("uc_open", err)?;
        Ok(handle)
    }

    pub fn error_message(&self, code: c_int) -> String {
        let text = unsafe { uc_strerror(code) };
        if text.is_null() {
            return format!("uc_err({code})");
        }
        unsafe { CStr::from_ptr(text) }
            .to_string_lossy()
            .into_owned()
    }

    pub fn check_error(&self, op: &'static str, code: c_int) -> Result<(), String> {
        if code == 0 {
            Ok(())
        } else {
            Err(format!("{op}: {}", self.error_message(code)))
        }
    }

    pub unsafe fn reg_read_raw(&self, handle: *mut UcEngine, regid: c_int) -> Result<u64, String> {
        let mut value = 0u64;
        let err = unsafe { uc_reg_read(handle, regid, (&mut value as *mut u64).cast()) };
        self.check_error("uc_reg_read", err)?;
        Ok(value)
    }

    pub unsafe fn reg_write_raw(
        &self,
        handle: *mut UcEngine,
        regid: c_int,
        value: u64,
    ) -> Result<(), String> {
        let err = unsafe { uc_reg_write(handle, regid, (&value as *const u64).cast()) };
        self.check_error("uc_reg_write", err)
    }

    pub unsafe fn reg_write_mmr_raw(
        &self,
        handle: *mut UcEngine,
        regid: c_int,
        value: &X86Mmr,
    ) -> Result<(), String> {
        let err = unsafe { uc_reg_write(handle, regid, (value as *const X86Mmr).cast()) };
        self.check_error("uc_reg_write", err)
    }

    pub unsafe fn mem_read_raw(
        &self,
        handle: *mut UcEngine,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, String> {
        let mut bytes = vec![0u8; size];
        unsafe { self.mem_read_into_raw(handle, address, &mut bytes)? };
        Ok(bytes)
    }

    pub unsafe fn mem_read_into_raw(
        &self,
        handle: *mut UcEngine,
        address: u64,
        buffer: &mut [u8],
    ) -> Result<(), String> {
        let err = unsafe {
            uc_mem_read(
                handle,
                address,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u64,
            )
        };
        self.check_error("uc_mem_read", err)
    }

    pub unsafe fn mem_write_raw(
        &self,
        handle: *mut UcEngine,
        address: u64,
        data: &[u8],
    ) -> Result<(), String> {
        let err = unsafe { uc_mem_write(handle, address, data.as_ptr().cast(), data.len() as u64) };
        self.check_error("uc_mem_write", err)
    }

    pub unsafe fn mem_map_raw(
        &self,
        handle: *mut UcEngine,
        address: u64,
        size: u64,
        perms: u32,
    ) -> Result<(), String> {
        let err = unsafe { uc_mem_map(handle, address, size, perms) };
        self.check_error("uc_mem_map", err)
    }

    pub unsafe fn mem_unmap_raw(
        &self,
        handle: *mut UcEngine,
        address: u64,
        size: u64,
    ) -> Result<(), String> {
        let err = unsafe { uc_mem_unmap(handle, address, size) };
        self.check_error("uc_mem_unmap", err)
    }

    pub unsafe fn mem_protect_raw(
        &self,
        handle: *mut UcEngine,
        address: u64,
        size: u64,
        perms: u32,
    ) -> Result<(), String> {
        let err = unsafe { uc_mem_protect(handle, address, size, perms) };
        self.check_error("uc_mem_protect", err)
    }

    pub unsafe fn emu_stop_raw(&self, handle: *mut UcEngine) -> Result<(), String> {
        let err = unsafe { uc_emu_stop(handle) };
        self.check_error("uc_emu_stop", err)
    }

    pub unsafe fn emu_start_raw(
        &self,
        handle: *mut UcEngine,
        begin: u64,
        until: u64,
        timeout: u64,
        count: usize,
    ) -> Result<(), String> {
        let err = unsafe { uc_emu_start(handle, begin, until, timeout, count) };
        self.check_error("uc_emu_start", err)
    }

    pub unsafe fn hook_add_code_raw(
        &self,
        handle: *mut UcEngine,
        callback: CodeHook,
        user_data: *mut c_void,
    ) -> Result<UcHook, String> {
        let mut hook = 0usize;
        let err = unsafe {
            uc_hook_add(
                handle,
                &mut hook,
                UC_HOOK_CODE,
                callback as *mut c_void,
                user_data,
                1,
                0,
            )
        };
        self.check_error("uc_hook_add", err)?;
        Ok(hook)
    }

    pub unsafe fn hook_add_block_raw(
        &self,
        handle: *mut UcEngine,
        callback: CodeHook,
        user_data: *mut c_void,
    ) -> Result<UcHook, String> {
        let mut hook = 0usize;
        let err = unsafe {
            uc_hook_add(
                handle,
                &mut hook,
                UC_HOOK_BLOCK,
                callback as *mut c_void,
                user_data,
                1,
                0,
            )
        };
        self.check_error("uc_hook_add", err)?;
        Ok(hook)
    }

    pub unsafe fn hook_add_mem_write_raw(
        &self,
        handle: *mut UcEngine,
        callback: MemHook,
        user_data: *mut c_void,
    ) -> Result<UcHook, String> {
        let mut hook = 0usize;
        let err = unsafe {
            uc_hook_add(
                handle,
                &mut hook,
                UC_HOOK_MEM_WRITE,
                callback as *mut c_void,
                user_data,
                1,
                0,
            )
        };
        self.check_error("uc_hook_add", err)?;
        Ok(hook)
    }

    pub unsafe fn hook_add_mem_prot_raw(
        &self,
        handle: *mut UcEngine,
        callback: MemProtHook,
        user_data: *mut c_void,
    ) -> Result<UcHook, String> {
        let mut hook = 0usize;
        let err = unsafe {
            uc_hook_add(
                handle,
                &mut hook,
                UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT,
                callback as *mut c_void,
                user_data,
                1,
                0,
            )
        };
        self.check_error("uc_hook_add", err)?;
        Ok(hook)
    }

    pub unsafe fn hook_add_mem_unmapped_raw(
        &self,
        handle: *mut UcEngine,
        callback: MemProtHook,
        user_data: *mut c_void,
    ) -> Result<UcHook, String> {
        let mut hook = 0usize;
        let err = unsafe {
            uc_hook_add(
                handle,
                &mut hook,
                UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                callback as *mut c_void,
                user_data,
                1,
                0,
            )
        };
        self.check_error("uc_hook_add", err)?;
        Ok(hook)
    }

    pub unsafe fn close_raw(&self, handle: *mut UcEngine) -> Result<(), String> {
        let err = unsafe { uc_close(handle) };
        self.check_error("uc_close", err)
    }
}

pub struct UnicornHandle<'a> {
    api: &'a UnicornApi,
    handle: *mut UcEngine,
}

impl UnicornHandle<'_> {
    pub fn raw(&self) -> *mut UcEngine {
        self.handle
    }

    pub fn mem_map(&mut self, address: u64, size: u64, perms: u32) -> Result<(), String> {
        let err = unsafe { uc_mem_map(self.handle, address, size, perms) };
        self.api.check_error("uc_mem_map", err)
    }

    pub fn mem_protect(&mut self, address: u64, size: u64, perms: u32) -> Result<(), String> {
        let err = unsafe { uc_mem_protect(self.handle, address, size, perms) };
        self.api.check_error("uc_mem_protect", err)
    }

    pub fn mem_write(&mut self, address: u64, data: &[u8]) -> Result<(), String> {
        unsafe { self.api.mem_write_raw(self.handle, address, data) }
    }

    pub fn mem_read(&self, address: u64, size: usize) -> Result<Vec<u8>, String> {
        unsafe { self.api.mem_read_raw(self.handle, address, size) }
    }

    pub fn reg_write(&mut self, regid: c_int, value: u64) -> Result<(), String> {
        unsafe { self.api.reg_write_raw(self.handle, regid, value) }
    }

    pub fn reg_read(&self, regid: c_int) -> Result<u64, String> {
        unsafe { self.api.reg_read_raw(self.handle, regid) }
    }

    pub fn reg_write_mmr(&mut self, regid: c_int, value: &X86Mmr) -> Result<(), String> {
        unsafe { self.api.reg_write_mmr_raw(self.handle, regid, value) }
    }

    pub fn emu_start(
        &mut self,
        begin: u64,
        until: u64,
        timeout: u64,
        count: usize,
    ) -> Result<(), String> {
        unsafe {
            self.api
                .emu_start_raw(self.handle, begin, until, timeout, count)
        }
    }

    pub fn emu_stop(&mut self) -> Result<(), String> {
        let err = unsafe { uc_emu_stop(self.handle) };
        self.api.check_error("uc_emu_stop", err)
    }

    pub fn add_code_hook(
        &mut self,
        callback: CodeHook,
        user_data: *mut c_void,
    ) -> Result<UcHook, String> {
        unsafe { self.api.hook_add_code_raw(self.handle, callback, user_data) }
    }
}

impl Drop for UnicornHandle<'_> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let _ = unsafe { self.api.close_raw(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}
