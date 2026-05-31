/// Declares a static `HookSignature` with named fields.
///
/// # Example
///
/// ```ignore
/// static CREATE_FILE_W: HookSignature = hook_sig!(
///     module: "kernel32.dll",
///     function: "CreateFileW",
///     abi: LogicalAbi::WinApi,
///     params: [
///         p!("lpFileName", ParamType::PCWStr),
///         p!("dwDesiredAccess", ParamType::Hex32),
///         p!("dwShareMode", ParamType::Hex32),
///         p!("lpSecurityAttributes", ParamType::SecurityAttributesPtr),
///         p!("dwCreationDisposition", ParamType::U32),
///         p!("dwFlagsAndAttributes", ParamType::Hex32),
///         p!("hTemplateFile", ParamType::Handle),
///     ],
///     ret: ReturnSpec::Handle,
/// );
/// ```
#[macro_export]
macro_rules! hook_sig {
    (
        module: $module:expr,
        function: $function:expr,
        abi: $abi:expr,
        params: [$($param:expr),* $(,)?],
        ret: $ret:expr $(,)?
    ) => {{
        $crate::hooks::signature::HookSignature {
            module: $module,
            function: $function,
            abi: $abi,
            params: &[$($param),*],
            ret: $ret,
            flags: $crate::hooks::types::HookFlags::empty(),
        }
    }};

    (
        module: $module:expr,
        function: $function:expr,
        abi: $abi:expr,
        params: [$($param:expr),* $(,)?],
        ret: $ret:expr,
        flags: $flags:expr $(,)?
    ) => {{
        $crate::hooks::signature::HookSignature {
            module: $module,
            function: $function,
            abi: $abi,
            params: &[$($param),*],
            ret: $ret,
            flags: $flags,
        }
    }};
}

/// Shorthand for constructing a `ParamSpec` with default direction and log policy.
///
/// # Example
///
/// ```ignore
/// p!("lpFileName", ParamType::PCWStr)
/// ```
#[macro_export]
macro_rules! param {
    ($name:expr, $ty:expr) => {{
        $crate::hooks::signature::ParamSpec::new($name, $ty)
    }};
    ($name:expr, $ty:expr, dir=$dir:expr) => {{
        $crate::hooks::signature::ParamSpec::with_dir($name, $ty, $dir)
    }};
    ($name:expr, $ty:expr, log=$log:expr) => {{
        $crate::hooks::signature::ParamSpec::with_log($name, $ty, $log)
    }};
}
