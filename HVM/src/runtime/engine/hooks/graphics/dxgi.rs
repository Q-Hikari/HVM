use super::*;

/// DXGI_ERROR_NOT_FOUND = 0x887A0002
const DXGI_ERROR_NOT_FOUND: u32 = 0x887A0002;

/// Layout of the synthetic IDXGIFactory vtable.
/// IUnknown (0x00..0x10) + IDXGIObject (0x18..0x30) + IDXGIFactory.
/// Method at offset 0x38 = EnumAdapters.
const VTABLE_SIZE: u64 = 0x48;
const VTABLE_ENUM_ADAPTERS_OFFSET: u64 = 0x38;
const VTABLE_MAKE_WINDOW_ASSOCIATION_OFFSET: u64 = 0x40;

/// Synthetic vtable method names for hook dispatch.
const METHOD_ENUM_ADAPTERS: &str = "__vm_dxgi_factory_EnumAdapters";
const METHOD_MAKE_WINDOW_ASSOCIATION: &str = "__vm_dxgi_factory_MakeWindowAssociation";
const METHOD_STUB: &str = "__vm_dxgi_factory_Stub";

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_dxgi_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("dxgi.dll", "CreateDXGIFactory") | ("dxgi.dll", "CreateDXGIFactory1") => true,
            ("dxgi.dll", "CreateDXGIFactory2") => true,
            ("dxgi.dll", METHOD_ENUM_ADAPTERS) => true,
            ("dxgi.dll", METHOD_MAKE_WINDOW_ASSOCIATION) => true,
            ("dxgi.dll", METHOD_STUB) => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("dxgi.dll", "CreateDXGIFactory") | ("dxgi.dll", "CreateDXGIFactory1") => {
                    self.dxgi_create_factory(ctx.raw(1))
                }
                ("dxgi.dll", "CreateDXGIFactory2") => self.dxgi_create_factory(ctx.raw(2)),
                ("dxgi.dll", METHOD_ENUM_ADAPTERS) => {
                    // EnumAdapters(Adapter, ppOutput) → DXGI_ERROR_NOT_FOUND (no adapters)
                    Ok(DXGI_ERROR_NOT_FOUND as u64)
                }
                ("dxgi.dll", METHOD_MAKE_WINDOW_ASSOCIATION) => Ok(0),
                ("dxgi.dll", METHOD_STUB) => Ok(0),
                _ => unreachable!("prechecked dispatch"),
            }
        })())
    }

    fn dxgi_create_factory(&mut self, pp_factory: u64) -> Result<u64, VmError> {
        if pp_factory == 0 {
            return Ok(0x80070057); // E_INVALIDARG
        }

        let vtable = self.dxgi_allocate_factory_vtable()?;
        let factory = self.alloc_process_heap_block(8, "dxgi:factory")?;
        self.write_pointer_value(factory, vtable)?;

        self.write_pointer_value(pp_factory, factory)?;
        Ok(0) // S_OK
    }

    fn dxgi_allocate_factory_vtable(&mut self) -> Result<u64, VmError> {
        let vtable = self.alloc_process_heap_block(VTABLE_SIZE, "dxgi:factory_vtable")?;

        // Fill the whole vtable with stub method pointers.
        let stub = self.ensure_dxgi_stub_binding();
        let stub_ptr_bytes = stub.to_le_bytes();
        let vtable_bytes = vec![stub_ptr_bytes; (VTABLE_SIZE / 8) as usize].concat();
        self.core
            .modules
            .memory_mut()
            .write(vtable, &vtable_bytes)?;

        // Override specific vtable slots.
        let enum_adapters = self.ensure_dxgi_method_binding(METHOD_ENUM_ADAPTERS);
        self.write_pointer_value(vtable + VTABLE_ENUM_ADAPTERS_OFFSET, enum_adapters)?;

        let make_window_assoc = self.ensure_dxgi_method_binding(METHOD_MAKE_WINDOW_ASSOCIATION);
        self.write_pointer_value(
            vtable + VTABLE_MAKE_WINDOW_ASSOCIATION_OFFSET,
            make_window_assoc,
        )?;

        Ok(vtable)
    }

    fn ensure_dxgi_stub_binding(&mut self) -> u64 {
        self.core
            .hooks
            .binding_address("dxgi.dll", METHOD_STUB)
            .unwrap_or_else(|| self.bind_hook_for_test("dxgi.dll", METHOD_STUB))
    }

    fn ensure_dxgi_method_binding(&mut self, method: &str) -> u64 {
        self.core
            .hooks
            .binding_address("dxgi.dll", method)
            .unwrap_or_else(|| self.bind_hook_for_test("dxgi.dll", method))
    }
}
