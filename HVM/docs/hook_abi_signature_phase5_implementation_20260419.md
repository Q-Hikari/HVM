# Phase 5: Full Family Migration — Implementation Report

**Date**: 2026-04-19
**Branch**: `hikari-v1`
**Scope**: All remaining DLL families — HookSignature definitions + registration wiring

## Summary

Phase 5 completes the "全家族迁移" (full family migration) stage of the Hook ABI Signature plan. Every remaining DLL family receives a dedicated `*_signatures.rs` file with full `HookSignature` definitions, and the registration wiring connects them into the hook registry.

Core deliverables:
1. **58 new signature files** covering all remaining DLL families
2. **70 modified files** — module declarations + `register_signatures()` calls
3. **~1666 new signatures** added on top of Phase 4's 1725, for a grand total of **~3391**
4. **100% coverage** of all meaningful (argc > 0) export functions

## Coverage Summary (After Phase 5)

### Family: `com`

| DLL | Signatures | File | Status |
|-----|-----------|------|--------|
| combase.dll | 26 | `com/combase_signatures.rs` | Phase 4 |
| ole32.dll | 52 | `com/ole32_signatures.rs` | Phase 4 |
| oleaut32.dll | 65 | `com/oleaut32_signatures.rs` | Phase 4 |
| oleacc.dll | 3 | `com/oleacc_signatures.rs` | **Phase 5 NEW** |
| oledlg.dll | 1 | `com/oledlg_signatures.rs` | **Phase 5 NEW** |
| rpcrt4.dll | 32 | `com/rpcrt4_signatures.rs` | Phase 4 |

### Family: `core`

| DLL | Signatures | File | Status |
|-----|-----------|------|--------|
| kernel32.dll | 392 | `core/kernel32_signatures.rs` | Phase 3 |
| ntdll.dll | 671 | `core/ntdll_signatures.rs` | Phase 3 |
| psapi.dll | 22 | `core/psapi_signatures.rs` | **Phase 5 NEW** |
| version.dll | 12 | `core/version_signatures.rs` | **Phase 5 NEW** |
| appmodel_runtime | 2 | `core/appmodel_runtime_signatures.rs` | **Phase 5 NEW** |
| featurestaging | 3 | `core/featurestaging_signatures.rs` | **Phase 5 NEW** |

### Family: `crt`

| DLL | Signatures | File | Status |
|-----|-----------|------|--------|
| msvcrt.dll | 99 | `crt/msvcrt_signatures.rs` | Phase 3 |
| variadic | 11 | `crt/variadic_signatures.rs` | Phase 4 |
| msvcp140.dll | 84 stubs | `crt/msvcp140_signatures.rs` | **Phase 5 NEW** |
| ucrt.dll | 22 | `crt/ucrt_signatures.rs` | **Phase 5 NEW** |
| vcruntime140.dll | 7 | `crt/vcruntime140_signatures.rs` | **Phase 5 NEW** |

### Family: `device`

| DLL | Signatures | File | Status |
|-----|-----------|------|--------|
| cabinet.dll | 21 | `device/cabinet_signatures.rs` | **Phase 5 NEW** |
| cfgmgr32.dll | 16 | `device/cfgmgr32_signatures.rs` | **Phase 5 NEW** |
| setupapi.dll | 16 | `device/setupapi_signatures.rs` | **Phase 5 NEW** |

### Family: `diagnostics`

| DLL | Signatures | File | Status |
|-----|-----------|------|--------|
| apphelp.dll | 9 | `diagnostics/apphelp_signatures.rs` | **Phase 5 NEW** |
| dbgcore.dll | 2 | `diagnostics/dbgcore_signatures.rs` | **Phase 5 NEW** |
| dbghelp.dll | 16 | `diagnostics/dbghelp_signatures.rs` | **Phase 5 NEW** |
| wer.dll | 19 | `diagnostics/wer_signatures.rs` | **Phase 5 NEW** |
| wevtapi.dll | 7 | `diagnostics/wevtapi_signatures.rs` | **Phase 5 NEW** |

### Family: `graphics`

| DLL | Signatures | File | Status |
|-----|-----------|------|--------|
| gdi32.dll | 109 | `graphics/gdi32_signatures.rs` | **Phase 5 NEW** |
| gdiplus.dll | 22 | `graphics/gdiplus_signatures.rs` | **Phase 5 NEW** |
| dxgi.dll | 6 | `graphics/dxgi_signatures.rs` | **Phase 5 NEW** |
| msimg32.dll | 2 | `graphics/msimg32_signatures.rs` | **Phase 5 NEW** |
| winmm.dll | 17 | `graphics/winmm_signatures.rs` | **Phase 5 NEW** |

### Family: `installer`

| DLL | Signatures | File | Status |
|-----|-----------|------|--------|
| msi.dll | 40 | `installer/msi_signatures.rs` | **Phase 5 NEW** |

### Family: `network`

| DLL | Signatures | File | Status |
|-----|-----------|------|--------|
| ws2_32.dll | 82 | `network/ws2_32_signatures.rs` | **Phase 5 NEW** |
| netapi32.dll | 38 | `network/netapi32_signatures.rs` | **Phase 5 NEW** |
| wldap32.dll | 39 | `network/wldap32_signatures.rs` | **Phase 5 NEW** |
| mpr.dll | 35 | `network/mpr_signatures.rs` | **Phase 5 NEW** |
| wininet.dll | 24 | `network/wininet_signatures.rs` | **Phase 5 NEW** |
| winhttp.dll | 16 | `network/winhttp_signatures.rs` | **Phase 5 NEW** |
| iphlpapi.dll | 10 | `network/iphlpapi_signatures.rs` | **Phase 5 NEW** |
| dnsapi.dll | 10 | `network/dnsapi_signatures.rs` | **Phase 5 NEW** |
| rasapi32.dll | 12 | `network/rasapi32_signatures.rs` | **Phase 5 NEW** |
| wlanapi.dll | 9 | `network/wlanapi_signatures.rs` | **Phase 5 NEW** |
| netutils.dll | 3 | `network/netutils_signatures.rs` | **Phase 5 NEW** |
| mswsock.dll | 1 | `network/mswsock_signatures.rs` | **Phase 5 NEW** |

### Family: `print`

| DLL | Signatures | File | Status |
|-----|-----------|------|--------|
| winspool.dll | 15 | `print/winspool_signatures.rs` | **Phase 5 NEW** |
| winspool_drv.dll | 15 | `print/winspool_drv_signatures.rs` | **Phase 5 NEW** |

### Family: `security`

| DLL | Signatures | File | Status |
|-----|-----------|------|--------|
| advapi32.dll | 116 | `security/advapi32_signatures.rs` | Phase 3 |
| cryptui.dll | 20 | `security/cryptui_signatures.rs` | **Phase 5 NEW** |
| crypt32.dll | 19 | `security/crypt32_signatures.rs` | **Phase 5 NEW** |
| bcrypt.dll | 17 | `security/bcrypt_signatures.rs` | **Phase 5 NEW** |
| wintrust.dll | 17 | `security/wintrust_signatures.rs` | **Phase 5 NEW** |
| secur32.dll | 16 | `security/secur32_signatures.rs` | **Phase 5 NEW** |
| ncrypt.dll | 14 | `security/ncrypt_signatures.rs` | **Phase 5 NEW** |
| eventing.dll | 14 | `security/eventing_signatures.rs` | **Phase 5 NEW** |
| cryptnet.dll | 4 | `security/cryptnet_signatures.rs` | **Phase 5 NEW** |
| fwpuclnt.dll | 7 | `security/fwpuclnt_signatures.rs` | **Phase 5 NEW** |

### Family: `shell_services`

| DLL | Signatures | File | Status |
|-----|-----------|------|--------|
| shell32.dll | 32 | `shell_services/shell32_signatures.rs` | **Phase 5 NEW** |
| shlwapi.dll | 27 | `shell_services/shlwapi_signatures.rs` | **Phase 5 NEW** |
| wtsapi32.dll | 21 | `shell_services/wtsapi32_signatures.rs` | **Phase 5 NEW** |
| urlmon.dll | 9 | `shell_services/urlmon_signatures.rs` | **Phase 5 NEW** |
| taskschd.dll | 5 | `shell_services/taskschd_signatures.rs` | **Phase 5 NEW** |
| propsys.dll | 3 | `shell_services/propsys_signatures.rs` | **Phase 5 NEW** |
| xmllite.dll | 1 | `shell_services/xmllite_signatures.rs` | **Phase 5 NEW** |

### Family: `ui`

| DLL | Signatures | File | Status |
|-----|-----------|------|--------|
| user32.dll | 261 | `ui/user32/user32_signatures.rs` | Phase 3 |
| mfc42u.dll | 716 | `ui/mfc42u_signatures.rs` | **Phase 5 NEW** |
| comdlg32.dll | 19 | `ui/comdlg32_signatures.rs` | **Phase 5 NEW** |
| uxtheme.dll | 12 | `ui/uxtheme_signatures.rs` | **Phase 5 NEW** |
| comctl32.dll | 7 | `ui/comctl32_signatures.rs` | **Phase 5 NEW** |
| imm32.dll | 3 | `ui/imm32_signatures.rs` | **Phase 5 NEW** |

## Phase 5 Coverage Statistics

| Metric | Count |
|--------|-------|
| Pre-Phase 5 signatures (Phase 3+4) | 1,725 |
| Phase 5 new signatures | ~1,666 |
| **Grand total** | **~3,391** |
| Phase 5 new signature files | 58 |
| Modified DLL files (wiring) | 70 |
| DLL families with full coverage | 12/12 (100%) |
| Meaningful exports with signatures | 100% |

## Intentionally Skipped Items

### ntdll.dll — 1,800 placeholder functions (argc=0)

These are stub-exported internal functions with no real parameter information. They serve as API surface entries but do not carry typed signatures. Categories:
- Nt/Zw system services: 674
- Rtl runtime functions: 762
- Ldr loader functions: 69
- Etw event tracing: 33
- Tp thread pool: 41
- Csr CSR client: 13
- Dbg debug support: 16
- Alpc ALPC: 15
- Other: 163

These remain as `definition("FuncName", 0)` entries in `ntdll.rs` and continue to work via the raw `arg(args, N)` dispatch path.

### msvcrt.dll — 21 C++ mangled names + data exports

9 C++ decorated names (exception/type_info constructors, new/delete operators) and 12 CRT data export symbols. Phase 3 explicitly documented these as "intentionally skipped."

## Signature File Categories

Phase 5 signature files fall into three patterns:

### Pattern A: Full Typed Signatures

Standard `HookSignature { ... }` blocks with typed `ParamSpec` entries. Used for most DLLs.

Example: `gdi32_signatures.rs` (109 entries, 1429 lines)
```rust
HookSignature {
    module: "gdi32.dll",
    function: "BitBlt",
    abi: LogicalAbi::WinApi,
    params: &[
        ParamSpec::new("hdc", Handle),
        ParamSpec::new("x", I32),
        ParamSpec::new("y", I32),
        ParamSpec::new("cx", I32),
        ParamSpec::new("cy", I32),
        ParamSpec::new("hdcSrc", Handle),
        ParamSpec::new("x1", I32),
        ParamSpec::new("y1", I32),
        ParamSpec::new("rop", U32),
    ],
    ret: ReturnSpec::Bool32,
    flags: HookFlags::empty(),
},
```

### Pattern B: C++ Mangled Name Stubs

Uses a `cpp_stub()` helper for C++ mangled exports. No typed parameters (opaque stubs).

Example: `msvcp140_signatures.rs` (84 entries, 109 lines)
```rust
const fn cpp_stub(function: &'static str) -> HookSignature {
    HookSignature {
        module: "msvcp140.dll",
        function,
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    }
}
```

### Pattern C: Ordinal Export Stubs

mfc42u.dll exports 716 functions by ordinal number. The signature file maps each ordinal to a stub signature.

Example: `mfc42u_signatures.rs` (716 entries, 724 lines)

## Wiring Changes

### Module declarations

Each family's `mod.rs` received `pub mod xxx_signatures;` declarations:

| Family | Added modules |
|--------|--------------|
| com | `oleacc_signatures`, `oledlg_signatures` |
| core | `appmodel_runtime_signatures`, `featurestaging_signatures`, `psapi_signatures`, `version_signatures` |
| crt | `msvcp140_signatures`, `ucrt_signatures`, `vcruntime140_signatures` |
| device | `cabinet_signatures`, `cfgmgr32_signatures`, `setupapi_signatures` |
| diagnostics | `apphelp_signatures`, `dbgcore_signatures`, `dbghelp_signatures`, `wer_signatures`, `wevtapi_signatures` |
| graphics | `dxgi_signatures`, `gdi32_signatures`, `gdiplus_signatures`, `msimg32_signatures`, `winmm_signatures` |
| installer | `msi_signatures` |
| network | All 12 `*_signatures` modules |
| print | `winspool_signatures`, `winspool_drv_signatures` |
| security | `bcrypt_signatures`, `crypt32_signatures`, `cryptnet_signatures`, `cryptui_signatures`, `eventing_signatures`, `fwpuclnt_signatures`, `ncrypt_signatures`, `secur32_signatures`, `wintrust_signatures` |
| shell_services | All 7 `*_signatures` modules |
| ui | `comctl32_signatures`, `comdlg32_signatures`, `imm32_signatures`, `mfc42u_signatures`, `uxtheme_signatures` |

### Registration calls

Each DLL's `register_xxx_hooks()` function received one additional line:

```rust
registry.register_signatures(super::xxx_signatures::XXX_SIGNATURES);
```

This follows the pattern established in Phase 3.

## Verification

- `cargo check` — zero errors (112 warnings, all pre-existing)
- `cargo test --lib` — 37 passed, 3 failed (all 3 failures pre-existing, unrelated to Phase 5)

## Next Steps

Per the migration plan, the final phase is:

- **Phase 6**: Cleanup — remove `HookDefinition`, `api_parameter_specs()`, `arg(args, i)` helper, redundant `arch_ptr`/`arch_i32` direct usage, and old test 32-bit assumptions.
