use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

const EXPORTS: &[(&str, LogicalAbi)] = &[
    ("GdipAlloc", LogicalAbi::WinApi),
    ("GdipBitmapLockBits", LogicalAbi::WinApi),
    ("GdipBitmapUnlockBits", LogicalAbi::WinApi),
    ("GdipCloneImage", LogicalAbi::WinApi),
    ("GdipCreateBitmapFromHBITMAP", LogicalAbi::WinApi),
    ("GdipCreateBitmapFromScan0", LogicalAbi::WinApi),
    ("GdipCreateBitmapFromStream", LogicalAbi::WinApi),
    ("GdipCreateFromHDC", LogicalAbi::WinApi),
    ("GdipDeleteGraphics", LogicalAbi::WinApi),
    ("GdipDisposeImage", LogicalAbi::WinApi),
    ("GdipDrawImageI", LogicalAbi::WinApi),
    ("GdipDrawImageRectI", LogicalAbi::WinApi),
    ("GdipFree", LogicalAbi::WinApi),
    ("GdipGetImageGraphicsContext", LogicalAbi::WinApi),
    ("GdipGetImageHeight", LogicalAbi::WinApi),
    ("GdipGetImagePalette", LogicalAbi::WinApi),
    ("GdipGetImagePaletteSize", LogicalAbi::WinApi),
    ("GdipGetImagePixelFormat", LogicalAbi::WinApi),
    ("GdipGetImageWidth", LogicalAbi::WinApi),
    ("GdipSetInterpolationMode", LogicalAbi::WinApi),
    ("GdiplusShutdown", LogicalAbi::WinApi),
    ("GdiplusStartup", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_gdiplus_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("gdiplus.dll", &EXPORTS);
}
