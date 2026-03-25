use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stdcall_definitions;

const EXPORTS: &[(&str, usize)] = &[
    ("GdipAlloc", 1),
    ("GdipBitmapLockBits", 5),
    ("GdipBitmapUnlockBits", 2),
    ("GdipCloneImage", 2),
    ("GdipCreateBitmapFromHBITMAP", 3),
    ("GdipCreateBitmapFromScan0", 6),
    ("GdipCreateBitmapFromStream", 2),
    ("GdipCreateFromHDC", 2),
    ("GdipDeleteGraphics", 1),
    ("GdipDisposeImage", 1),
    ("GdipDrawImageI", 4),
    ("GdipDrawImageRectI", 6),
    ("GdipFree", 1),
    ("GdipGetImageGraphicsContext", 2),
    ("GdipGetImageHeight", 2),
    ("GdipGetImagePalette", 3),
    ("GdipGetImagePaletteSize", 2),
    ("GdipGetImagePixelFormat", 2),
    ("GdipGetImageWidth", 2),
    ("GdipSetInterpolationMode", 2),
    ("GdiplusShutdown", 1),
    ("GdiplusStartup", 3),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct GdiplusHookLibrary;

impl HookLibrary for GdiplusHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stdcall_definitions("gdiplus.dll", EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_gdiplus_hooks(registry: &mut HookRegistry) {
    registry.register_library(&GdiplusHookLibrary);
}
