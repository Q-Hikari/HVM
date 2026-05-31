use smallvec::SmallVec;

/// Minimal snapshot of ABI-relevant state at the moment of a hook call.
///
/// Used for callback frame preparation and continuation logic.
/// Fields will be expanded in later phases as needed.
#[derive(Debug, Clone)]
pub struct AbiSnapshot {
    /// Whether the callee is responsible for stack cleanup (stdcall).
    pub callee_cleanup: bool,
    /// Number of bytes the callee should pop from the stack (x86 only).
    pub callee_stack_pop: u32,
}

impl Default for AbiSnapshot {
    fn default() -> Self {
        Self {
            callee_cleanup: false,
            callee_stack_pop: 0,
        }
    }
}

/// Raw arguments captured from the guest CPU state at the moment of a hook call.
///
/// Uses `SmallVec<[u64; 8]>` to avoid heap allocation for the common case
/// of ≤8 parameters.
#[derive(Debug, Clone)]
pub struct RawCallFrame {
    pub args: SmallVec<[u64; 8]>,
    pub return_address: Option<u64>,
    pub stack_pointer: u64,
    #[allow(dead_code)]
    pub instruction_pointer: u64,
    #[allow(dead_code)]
    pub abi_snapshot: AbiSnapshot,
}

impl RawCallFrame {
    /// Returns the raw argument at the given index, or 0 if out of bounds.
    #[allow(dead_code)]
    pub fn arg(&self, index: usize) -> u64 {
        self.args.get(index).copied().unwrap_or(0)
    }

    /// Returns the number of captured arguments.
    #[allow(dead_code)]
    pub fn argc(&self) -> usize {
        self.args.len()
    }
}

/// The result of preparing a callback invocation frame.
///
/// Contains the new CPU state that should be applied to invoke the callback.
#[derive(Debug, Clone)]
pub struct PreparedCallbackFrame {
    /// New stack pointer value (RSP/ESP after frame setup).
    #[allow(dead_code)]
    pub new_sp: u64,
    /// New instruction pointer (RIP/EIP = callback address).
    #[allow(dead_code)]
    pub new_pc: u64,
    /// Whether callee-saved registers need restoration after the callback returns.
    #[allow(dead_code)]
    pub save_callee_saved: bool,
    /// Number of bytes to add to SP when cleaning up after the callback returns
    /// (for stdcall callbacks where the callee cleans the stack).
    pub callee_cleanup_bytes: u32,
}
