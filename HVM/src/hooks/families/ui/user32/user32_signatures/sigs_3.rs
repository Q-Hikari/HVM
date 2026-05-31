use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{HookFlags, LogicalAbi, ParamDirection::*, ParamType::*};

pub(super) static USER32_SIGS_3: &[HookSignature] = &[
    HookSignature {
        module: "user32.dll",
        function: "LoadStringW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hInstance", ModuleHandle),
            ParamSpec::new("uID", U32),
            ParamSpec::new("lpBuffer", PWStr),
            ParamSpec::new("cchBufferMax", I32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // ── Window update / coordinate mapping ───────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "LockWindowUpdate",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hWndLock", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "MapDialogRect",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hDlg", Handle),
            ParamSpec::with_dir("lpRect", OpaqueStructPtr("RECT"), InOut),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Keyboard mapping ─────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "MapVirtualKeyExW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("uCode", U32),
            ParamSpec::new("uMapType", U32),
            ParamSpec::new("dwhkl", GuestPtr),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "MapVirtualKeyW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("uCode", U32),
            ParamSpec::new("uMapType", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Coordinate mapping ───────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "MapWindowPoints",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWndFrom", Handle),
            ParamSpec::new("hWndTo", Handle),
            ParamSpec::with_dir("lpPoints", OpaqueStructPtr("POINT"), InOut),
            ParamSpec::new("cPoints", U32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // ── Sound / message ──────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "MessageBeep",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("uType", U32)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Menu manipulation ────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "ModifyMenuW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hMnu", Handle),
            ParamSpec::new("uPosition", U32),
            ParamSpec::new("uFlags", Hex32),
            ParamSpec::new("uIDNewItem", PointerSizedUInt),
            ParamSpec::new("lpNewItem", PCWStr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Monitor ──────────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "MonitorFromPoint",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("pt", PointerSizedUInt),
            ParamSpec::new("dwFlags", U32),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "MonitorFromRect",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lprc", OpaqueStructPtr("RECT")),
            ParamSpec::new("dwFlags", U32),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "MonitorFromWindow",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("dwFlags", U32),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ── Wait / event ─────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "MsgWaitForMultipleObjects",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("nCount", U32),
            ParamSpec::new("pHandles", GuestPtr),
            ParamSpec::new("fWaitAll", Bool32),
            ParamSpec::new("dwMilliseconds", U32),
            ParamSpec::new("dwWakeMask", Hex32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Accessibility event ──────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "NotifyWinEvent",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("event", U32),
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("idObject", I32),
            ParamSpec::new("idChild", I32),
        ],
        ret: ReturnSpec::Void,
        flags: HookFlags::empty(),
    },
    // ── Character conversion ─────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "OemToCharBuffA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpszSrc", PCStr),
            ParamSpec::new("lpszDst", PStr),
            ParamSpec::new("cchDstLength", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Rect manipulation ────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "OffsetRect",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("lprc", OpaqueStructPtr("RECT"), InOut),
            ParamSpec::new("dx", I32),
            ParamSpec::new("dy", I32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Clipboard ────────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "OpenClipboard",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hWndNewOwner", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Message queue ────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "PeekMessageA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("lpMsg", OpaqueStructPtr("MSG"), Out),
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("wMsgFilterMin", U32),
            ParamSpec::new("wMsgFilterMax", U32),
            ParamSpec::new("wRemoveMsg", Hex32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "PostThreadMessageW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("dwThreadId", U32),
            ParamSpec::new("Msg", U32),
            ParamSpec::new("wParam", PointerSizedUInt),
            ParamSpec::new("lParam", PointerSizedInt),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Point-in-rect / point hit-test ───────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "PtInRect",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lprc", OpaqueStructPtr("RECT")),
            ParamSpec::new("pt", PointerSizedUInt),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "RealChildWindowFromPoint",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hwndParent", Handle),
            ParamSpec::new("ptParentClientArea", PointerSizedUInt),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ── Window redraw ────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "RedrawWindow",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("lprcUpdate", OpaqueStructPtr("RECT")),
            ParamSpec::new("hrgnUpdate", Handle),
            ParamSpec::new("flags", Hex32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Window class registration ────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "RegisterClassW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpWndClass", OpaqueStructPtr("WNDCLASSW"))],
        ret: ReturnSpec::U16,
        flags: HookFlags::empty(),
    },
    // ── Clipboard format / message registration ──────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "RegisterClipboardFormatW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpszFormat", PCWStr)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "RegisterWindowMessageW",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("lpString", PCWStr)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Mouse capture ────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "ReleaseCapture",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Menu manipulation ────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "RemoveMenu",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hMenu", Handle),
            ParamSpec::new("uPosition", U32),
            ParamSpec::new("uFlags", Hex32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Window property ──────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "RemovePropW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("lpString", PCWStr),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ── DDE helper ───────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "ReuseDDElParam",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lParam", PointerSizedInt),
            ParamSpec::new("msgIn", U32),
            ParamSpec::new("cmdIn", U32),
            ParamSpec::new("cmdOut", U32),
            ParamSpec::new("dataOut", PointerSizedUInt),
        ],
        ret: ReturnSpec::PointerSizedInt,
        flags: HookFlags::empty(),
    },
    // ── Coordinate conversion ────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "ScreenToClient",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::with_dir("lpPoint", OpaqueStructPtr("POINT"), InOut),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ══════════════════════════════════════════════════════════════════════
    // Batch 5 – Scrolling, dialog messages, window state setters, menu
    //           manipulation, keyboard input, and misc UI functions
    // ══════════════════════════════════════════════════════════════════════

    // ── Scrolling ────────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "ScrollWindow",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("XAmount", I32),
            ParamSpec::new("YAmount", I32),
            ParamSpec::new("lpRect", OpaqueStructPtr("RECT")),
            ParamSpec::new("lpClipRect", OpaqueStructPtr("RECT")),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Dialog message ───────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SendDlgItemMessageA",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hDlg", Handle),
            ParamSpec::new("nIDDlgItem", I32),
            ParamSpec::new("Msg", U32),
            ParamSpec::new("wParam", PointerSizedUInt),
            ParamSpec::new("lParam", PointerSizedInt),
        ],
        ret: ReturnSpec::PointerSizedUInt,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SendDlgItemMessageW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hDlg", Handle),
            ParamSpec::new("nIDDlgItem", I32),
            ParamSpec::new("Msg", U32),
            ParamSpec::new("wParam", PointerSizedUInt),
            ParamSpec::new("lParam", PointerSizedInt),
        ],
        ret: ReturnSpec::PointerSizedUInt,
        flags: HookFlags::empty(),
    },
    // ── Message (timeout) ────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SendMessageTimeoutW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("Msg", U32),
            ParamSpec::new("wParam", PointerSizedUInt),
            ParamSpec::new("lParam", PointerSizedInt),
            ParamSpec::new("fuFlags", U32),
            ParamSpec::new("uTimeout", U32),
            ParamSpec::with_dir("lpdwResult", PointerSizedUInt, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Window (active / capture / focus / foreground) ───────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetActiveWindow",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hWnd", Handle)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetCapture",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hWnd", Handle)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ── Window class ─────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetClassLongW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("nIndex", I32),
            ParamSpec::new("dwNewLong", I32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Clipboard ────────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetClipboardData",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("uFormat", U32),
            ParamSpec::new("hMem", Handle),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ── Cursor ───────────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetCursor",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hCursor", Handle)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetCursorPos",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("X", I32), ParamSpec::new("Y", I32)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Window (focus / foreground) ──────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetFocus",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hWnd", Handle)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetForegroundWindow",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hWnd", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Gesture ──────────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetGestureConfig",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hwnd", Handle),
            ParamSpec::new("dwReserved", U32),
            ParamSpec::new("cIDs", U32),
            ParamSpec::new("pGestureConfig", GuestPtr),
            ParamSpec::new("cbSize", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Window (layered) ─────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetLayeredWindowAttributes",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("crKey", U32),
            ParamSpec::new("bAlpha", U32),
            ParamSpec::new("dwFlags", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Menu ─────────────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetMenu",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("hMenu", Handle),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetMenuDefaultItem",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hMenu", Handle),
            ParamSpec::new("uItem", U32),
            ParamSpec::new("fByPos", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetMenuItemBitmaps",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hMenu", Handle),
            ParamSpec::new("uPosition", U32),
            ParamSpec::new("uFlags", U32),
            ParamSpec::new("hBitmapUnchecked", Handle),
            ParamSpec::new("hBitmapChecked", Handle),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetMenuItemInfoW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hMenu", Handle),
            ParamSpec::new("uItem", U32),
            ParamSpec::new("fByPosition", Bool32),
            ParamSpec::new("lpmii", OpaqueStructPtr("MENUITEMINFOW")),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Window (parent) ──────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetParent",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWndChild", Handle),
            ParamSpec::new("hWndNewParent", Handle),
        ],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ── Window property ──────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetPropW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("lpString", PCWStr),
            ParamSpec::new("hData", Handle),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Rect ─────────────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetRect",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("lprc", OpaqueStructPtr("RECT"), Out),
            ParamSpec::new("xLeft", I32),
            ParamSpec::new("yTop", I32),
            ParamSpec::new("xRight", I32),
            ParamSpec::new("yBottom", I32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetRectEmpty",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::with_dir("lprc", OpaqueStructPtr("RECT"), Out)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Scroll (setters) ─────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetScrollInfo",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("nBar", I32),
            ParamSpec::new("lpsi", OpaqueStructPtr("SCROLLINFO")),
            ParamSpec::new("bRedraw", Bool32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetScrollPos",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("nBar", I32),
            ParamSpec::new("nPos", I32),
            ParamSpec::new("bRedraw", Bool32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetScrollRange",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("nBar", I32),
            ParamSpec::new("nMinPos", I32),
            ParamSpec::new("nMaxPos", I32),
            ParamSpec::new("bRedraw", Bool32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Window (help / long ptr) ─────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetWindowContextHelpId",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("dwContextHelpId", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetWindowLongPtrW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("nIndex", I32),
            ParamSpec::new("dwNewLong", PointerSizedInt),
        ],
        ret: ReturnSpec::PointerSizedInt,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetWindowLongW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("nIndex", I32),
            ParamSpec::new("dwNewLong", I32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // ── Window (placement / region / text) ───────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SetWindowPlacement",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("lpwndpl", OpaqueStructPtr("WINDOWPLACEMENT")),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetWindowRgn",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("hRgn", Handle),
            ParamSpec::new("bRedraw", Bool32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "SetWindowTextW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("lpString", PCWStr),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Caret / popup / scrollbar ────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "ShowCaret",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hWnd", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "ShowOwnedPopups",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("fShow", Bool32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "ShowScrollBar",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("wBar", I32),
            ParamSpec::new("bShow", Bool32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Rect (subtraction) ───────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "SubtractRect",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("lprcDst", OpaqueStructPtr("RECT"), Out),
            ParamSpec::new("lprcSrc1", OpaqueStructPtr("RECT")),
            ParamSpec::new("lprcSrc2", OpaqueStructPtr("RECT")),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Text output ──────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "TabbedTextOutW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hDC", Handle),
            ParamSpec::new("X", I32),
            ParamSpec::new("Y", I32),
            ParamSpec::new("lpString", PCWStr),
            ParamSpec::new("nCount", I32),
            ParamSpec::new("nTabPositions", I32),
            ParamSpec::new("lpnTabStopPositions", GuestPtr),
            ParamSpec::new("nTabOrigin", I32),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // ── Keyboard input ───────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "ToUnicodeEx",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("wVirtKey", U32),
            ParamSpec::new("wScanCode", U32),
            ParamSpec::new("lpKeyState", GuestPtr),
            ParamSpec::with_dir("pwszBuff", PWStr, Out),
            ParamSpec::new("cchBuff", I32),
            ParamSpec::new("wFlags", U32),
            ParamSpec::new("dwhkl", GuestPtr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // ── Mouse tracking ───────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "TrackMouseEvent",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::with_dir(
            "lpEventTrack",
            OpaqueStructPtr("TRACKMOUSEEVENT"),
            InOut,
        )],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Menu (popup) ─────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "TrackPopupMenu",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hMenu", Handle),
            ParamSpec::new("uFlags", U32),
            ParamSpec::new("x", I32),
            ParamSpec::new("y", I32),
            ParamSpec::new("nReserved", I32),
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("prcRect", OpaqueStructPtr("RECT")),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Accelerator ──────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "TranslateAcceleratorW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("hAccTable", Handle),
            ParamSpec::new("lpMsg", OpaqueStructPtr("MSG")),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    // ══════════════════════════════════════════════════════════════════════
    // Batch 6 – MDI accel, rect union, DDE unpack, class unregister,
    //           layered window, validation, idle wait, point-to-window,
    //           WinHelp, and cdecl variadic string formatting
    // ══════════════════════════════════════════════════════════════════════

    // ── MDI accelerator ──────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "TranslateMDISysAccel",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWndClient", Handle),
            ParamSpec::new("lpMsg", OpaqueStructPtr("MSG")),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Rect (union) ─────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "UnionRect",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::with_dir("lprcDst", OpaqueStructPtr("RECT"), Out),
            ParamSpec::new("lprcSrc1", OpaqueStructPtr("RECT")),
            ParamSpec::new("lprcSrc2", OpaqueStructPtr("RECT")),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── DDE helper ───────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "UnpackDDElParam",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("msg", U32),
            ParamSpec::new("lParam", PointerSizedInt),
            ParamSpec::with_dir("uiHi", GuestPtr, Out),
            ParamSpec::with_dir("uiLo", GuestPtr, Out),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Window class ─────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "UnregisterClassW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("lpClassName", PCWStr),
            ParamSpec::new("hInstance", ModuleHandle),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Window (layered) ─────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "UpdateLayeredWindow",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("hdcDst", Handle),
            ParamSpec::new("pptDst", GuestPtr),
            ParamSpec::new("psize", GuestPtr),
            ParamSpec::new("hdcSrc", Handle),
            ParamSpec::new("pptSrc", GuestPtr),
            ParamSpec::new("crKey", U32),
            ParamSpec::new("pblend", GuestPtr),
            ParamSpec::new("dwFlags", U32),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Window (update) ──────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "UpdateWindow",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("hWnd", Handle)],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Rect (validation) ────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "ValidateRect",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWnd", Handle),
            ParamSpec::new("lpRect", OpaqueStructPtr("RECT")),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Process idle wait ────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "WaitForInputIdle",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hProcess", Handle),
            ParamSpec::new("dwMilliseconds", U32),
        ],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    // ── Message (wait) ───────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "WaitMessage",
        abi: LogicalAbi::WinApi,
        params: &[],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── Point-to-window ──────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "WindowFromPoint",
        abi: LogicalAbi::WinApi,
        params: &[ParamSpec::new("Point", PointerSizedUInt)],
        ret: ReturnSpec::Pointer,
        flags: HookFlags::empty(),
    },
    // ── Help ─────────────────────────────────────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "WinHelpW",
        abi: LogicalAbi::WinApi,
        params: &[
            ParamSpec::new("hWndMain", Handle),
            ParamSpec::new("lpszHelp", PCWStr),
            ParamSpec::new("uCommand", U32),
            ParamSpec::new("dwData", PointerSizedUInt),
        ],
        ret: ReturnSpec::Bool32,
        flags: HookFlags::empty(),
    },
    // ── String formatting (cdecl variadic) ───────────────────────────────
    HookSignature {
        module: "user32.dll",
        function: "wsprintfA",
        abi: LogicalAbi::VariadicCdecl,
        params: &[
            ParamSpec::new("lpOut", PStr),
            ParamSpec::new("lpFmt", PCStr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "user32.dll",
        function: "wsprintfW",
        abi: LogicalAbi::VariadicCdecl,
        params: &[
            ParamSpec::new("lpOut", PWStr),
            ParamSpec::new("lpFmt", PCWStr),
        ],
        ret: ReturnSpec::I32,
        flags: HookFlags::empty(),
    },
];
