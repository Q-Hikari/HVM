use super::*;

impl WindowsProcessEnvironment {
    /// Returns the fixed offsets for the current architecture mirror.
    pub fn offsets(&self) -> ProcessEnvironmentOffsets {
        self.offsets
    }

    /// Returns the current layout bases exposed to the rest of the runtime.
    pub fn layout(&self) -> ProcessEnvironmentLayout {
        self.layout
    }

    pub fn arch(&self) -> &'static ArchSpec {
        self.arch
    }

    /// Returns the current TEB base.
    pub fn current_teb(&self) -> u64 {
        self.current_teb_base
    }

    /// Returns whether the mirrored process-environment pages need rematerialization.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Returns the current PEB base.
    pub fn current_peb(&self) -> u64 {
        self.layout.peb_base
    }

    pub(in crate::runtime::windows_env) fn pointer_size(&self) -> usize {
        self.arch.pointer_size
    }
}
