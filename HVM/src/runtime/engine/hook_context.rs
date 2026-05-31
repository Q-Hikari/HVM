use crate::arch::ArchSpec;
use crate::error::VmError;
use crate::hooks::signature::HookSignature;

/// Typed context provided to hook handlers.
///
/// Wraps the raw argument slice, hook signature, and architecture spec,
/// providing typed access to parameters without requiring the handler to
/// know ABI details.
///
/// Constructed at the dispatch entry point and passed to family dispatchers.
/// Handlers use `ctx.raw(i)` for raw access or `ctx.get::<T>(i)` for typed
/// access via the `FromHookParam` trait.
pub struct HookContext<'a> {
    pub signature: &'a HookSignature,
    args: &'a [u64],
    #[allow(dead_code)] // Used by future arch-aware FromHookParam implementations
    pub arch: &'a ArchSpec,
}

impl<'a> HookContext<'a> {
    /// Creates a new hook context.
    pub fn new(signature: &'a HookSignature, args: &'a [u64], arch: &'a ArchSpec) -> Self {
        Self {
            signature,
            args,
            arch,
        }
    }

    /// Returns the raw `u64` argument at the given index, or 0 if out of bounds.
    pub fn raw(&self, index: usize) -> u64 {
        self.args.get(index).copied().unwrap_or(0)
    }

    /// Returns the raw argument slice (for backward compat with `args.arg(i)`).
    #[allow(dead_code)] // Used during Step 4 handler migration
    pub fn args(&self) -> &'a [u64] {
        self.args
    }

    /// Returns the module name of this hook.
    #[allow(dead_code)] // Used during Step 4 handler migration
    pub fn module(&self) -> &'static str {
        self.signature.module
    }

    /// Returns the function name of this hook.
    pub fn function(&self) -> &'static str {
        self.signature.function
    }

    /// Returns the number of captured arguments.
    #[allow(dead_code)] // Used during Step 4 handler migration
    pub fn argc(&self) -> usize {
        self.args.len()
    }

    /// Returns the ParamSpec for the parameter at `index`, if available.
    #[allow(dead_code)] // Used during Step 4 handler migration
    pub fn param_spec(&self, index: usize) -> Option<&'a crate::hooks::signature::ParamSpec> {
        self.signature.params.get(index)
    }

    /// Decodes a typed value from the parameter at `index` using the
    /// `FromHookParam` trait.
    pub fn get<T: FromHookParam>(&self, index: usize) -> Result<T, VmError> {
        T::decode(self, index)
    }
}

/// Trait for decoding a typed value from a raw hook parameter.
///
/// Implementors specify how to extract a meaningful Rust type from the
/// raw `u64` argument. The `HookContext` provides architecture info
/// for arch-aware types.
///
/// # Example
///
/// ```ignore
/// let handle: u32 = ctx.get(0)?;
/// let flags: u64 = ctx.get(1)?;
/// ```
pub trait FromHookParam: Sized {
    /// Decodes this type from the parameter at `index`.
    fn decode(ctx: &HookContext<'_>, index: usize) -> Result<Self, VmError>;
}

// ── Core scalar FromHookParam implementations ────────────────────────────

impl FromHookParam for u32 {
    fn decode(ctx: &HookContext<'_>, index: usize) -> Result<Self, VmError> {
        Ok(ctx.raw(index) as u32)
    }
}

impl FromHookParam for i32 {
    fn decode(ctx: &HookContext<'_>, index: usize) -> Result<Self, VmError> {
        Ok(ctx.raw(index) as u32 as i32)
    }
}

impl FromHookParam for u64 {
    fn decode(ctx: &HookContext<'_>, index: usize) -> Result<Self, VmError> {
        Ok(ctx.raw(index))
    }
}

impl FromHookParam for i64 {
    fn decode(ctx: &HookContext<'_>, index: usize) -> Result<Self, VmError> {
        Ok(ctx.raw(index) as i64)
    }
}

impl FromHookParam for bool {
    fn decode(ctx: &HookContext<'_>, index: usize) -> Result<Self, VmError> {
        Ok(ctx.raw(index) != 0)
    }
}

impl FromHookParam for u16 {
    fn decode(ctx: &HookContext<'_>, index: usize) -> Result<Self, VmError> {
        Ok(ctx.raw(index) as u16)
    }
}

impl FromHookParam for usize {
    fn decode(ctx: &HookContext<'_>, index: usize) -> Result<Self, VmError> {
        Ok(ctx.raw(index) as usize)
    }
}

/// Reader for variadic arguments beyond the fixed parameter prefix.
///
/// Given a call frame, this reader can sequentially read variadic arguments
/// that were captured beyond the fixed parameter count.  For variadic
/// functions the frame capture layer reads additional "extra" arguments
/// past the declared fixed parameters; this reader indexes into that tail.
///
/// # Usage
///
/// ```ignore
/// let mut reader = VariadicArgReader::new(&frame, fixed_count);
/// let first_var_arg = reader.next();
/// let second_var_arg = reader.next();
/// ```
#[allow(dead_code)]
pub struct VariadicArgReader<'a> {
    args: &'a [u64],
    /// Index into the variadic tail (0 = first variadic arg).
    variadic_index: usize,
    /// The index of the first variadic arg in the full args list.
    fixed_count: usize,
}

#[allow(dead_code)]
impl<'a> VariadicArgReader<'a> {
    /// Creates a new reader starting before the first variadic argument.
    ///
    /// `fixed_count` is the number of declared (non-variadic) parameters --
    /// typically `signature.argc()`.
    pub fn new(args: &'a [u64], fixed_count: usize) -> Self {
        Self {
            args,
            variadic_index: 0,
            fixed_count,
        }
    }

    /// Reads the next variadic argument as a raw `u64`.
    ///
    /// Returns 0 if the args do not contain enough captured arguments.
    pub fn next(&mut self) -> u64 {
        let index = self.fixed_count + self.variadic_index;
        self.variadic_index += 1;
        self.args.get(index).copied().unwrap_or(0)
    }

    /// Reads the next variadic argument as a pointer-sized value.
    ///
    /// On x86 the upper 32 bits are zero (identical to `next()`).
    pub fn next_ptr(&mut self) -> u64 {
        self.next()
    }

    /// Returns the number of variadic arguments that have been read so far.
    pub fn read_count(&self) -> usize {
        self.variadic_index
    }

    /// Resets the reader to the first variadic argument.
    pub fn reset(&mut self) {
        self.variadic_index = 0;
    }

    /// Returns the total number of variadic arguments available.
    ///
    /// This is `args.len() - fixed_count`, floored at 0.
    pub fn available(&self) -> usize {
        self.args.len().saturating_sub(self.fixed_count)
    }
}
