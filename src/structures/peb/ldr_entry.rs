use crate::structures::utils::*;

// _LDR_DATA_TABLE_ENTRY offsets by version and architecture.
//
// Sources (Vergilius Project):
//   x64 Vista  — /kernels/x64/windows-vista/sp2/_LDR_DATA_TABLE_ENTRY  (0xc8)
//   x64 Win7   — /kernels/x64/windows-7/sp1/_LDR_DATA_TABLE_ENTRY      (0xe0)
//   x64 Win8   — /kernels/x64/windows-8/rtm/_LDR_DATA_TABLE_ENTRY      (0x110)
//   x64 Win10  — /kernels/x64/windows-10/22h2/_LDR_DATA_TABLE_ENTRY    (0x120)
//   x64 Win11  — /kernels/x64/windows-11/24h2/_LDR_DATA_TABLE_ENTRY    (0x138)
//   x86 Win7   — /kernels/x86/windows-7/sp1/_LDR_DATA_TABLE_ENTRY      (0x78)
//   x86 Win10  — /kernels/x86/windows-10/22h2/_LDR_DATA_TABLE_ENTRY    (0xa8)
//
// Fields shared across ALL versions (same offset) are defined once in the
// `common_x64` / `common_x86` blocks and re-exported by each version module.

pub mod offsets {
    // -------------------------------------------------------------------------
    // x64 — fields stable across Vista → Win11
    // -------------------------------------------------------------------------
    mod common_x64 {
        pub const IN_LOAD_ORDER_LINKS: usize = 0x00; // _LIST_ENTRY
        pub const IN_MEMORY_ORDER_LINKS: usize = 0x10; // _LIST_ENTRY
        pub const IN_INIT_ORDER_LINKS: usize = 0x20; // _LIST_ENTRY
        pub const DLL_BASE: usize = 0x30; // VOID*
        pub const ENTRY_POINT: usize = 0x38; // VOID*
        pub const SIZE_OF_IMAGE: usize = 0x40; // ULONG
        pub const FULL_DLL_NAME: usize = 0x48; // _UNICODE_STRING (Length=0x48, MaxLength=0x4a, Buffer=0x50)
        pub const BASE_DLL_NAME: usize = 0x58; // _UNICODE_STRING (Length=0x58, MaxLength=0x5a, Buffer=0x60)
        pub const FLAGS: usize = 0x68; // ULONG
        pub const OBSOLETE_LOAD_COUNT: usize = 0x6c; // USHORT
        pub const TLS_INDEX: usize = 0x6e; // USHORT
        pub const HASH_LINKS: usize = 0x70; // _LIST_ENTRY
        pub const TIME_DATE_STAMP: usize = 0x80; // ULONG
    }

    /// x64 Vista (0xc8) — legacy fields, no DdagNode.
    pub mod x64_vista {
        pub use super::common_x64::*;
        pub const ENTRY_POINT_ACTIVATION_CONTEXT: usize = 0x88; // _ACTIVATION_CONTEXT*
        pub const PATCH_INFORMATION: usize = 0x90; // VOID*
        pub const FORWARDER_LINKS: usize = 0x98; // _LIST_ENTRY
        pub const SERVICE_TAG_LINKS: usize = 0xa8; // _LIST_ENTRY
        pub const STATIC_LINKS: usize = 0xb8; // _LIST_ENTRY
        // Total size: 0xc8
    }

    /// x64 Win7 (0xe0) — adds ContextInformation, OriginalBase, LoadTime.
    pub mod x64_win7 {
        pub use super::x64_vista::*;
        pub const CONTEXT_INFORMATION: usize = 0xc8; // VOID*
        pub const ORIGINAL_BASE: usize = 0xd0; // ULONGLONG
        pub const LOAD_TIME: usize = 0xd8; // _LARGE_INTEGER
        // Total size: 0xe0
    }

    /// x64 Win8 (0x110) — replaces legacy link fields with DdagNode tree.
    pub mod x64_win8 {
        pub use super::common_x64::*;
        pub const ENTRY_POINT_ACTIVATION_CONTEXT: usize = 0x88;
        pub const PATCH_INFORMATION: usize = 0x90;
        pub const DDAG_NODE: usize = 0x98; // _LDR_DDAG_NODE*
        pub const NODE_MODULE_LINK: usize = 0xa0; // _LIST_ENTRY
        pub const SNAP_CONTEXT: usize = 0xb0; // _LDRP_DLL_SNAP_CONTEXT*
        pub const PARENT_DLL_BASE: usize = 0xb8; // VOID*
        pub const SWITCH_BACK_CONTEXT: usize = 0xc0; // VOID*
        pub const BASE_ADDRESS_INDEX_NODE: usize = 0xc8; // _RTL_BALANCED_NODE (0x18 bytes)
        pub const MAPPING_INFO_INDEX_NODE: usize = 0xe0; // _RTL_BALANCED_NODE
        pub const ORIGINAL_BASE: usize = 0xf8; // ULONGLONG
        pub const LOAD_TIME: usize = 0x100; // _LARGE_INTEGER
        pub const BASE_NAME_HASH_VALUE: usize = 0x108; // ULONG
        pub const LOAD_REASON: usize = 0x10c; // enum _LDR_DLL_LOAD_REASON
        // Total size: 0x110
    }

    /// x64 Win10 22H2 (0x120) — adds ImplicitPathOptions … SigningLevel.
    pub mod x64_win10 {
        pub use super::x64_win8::*;
        pub const IMPLICIT_PATH_OPTIONS: usize = 0x110; // ULONG
        pub const REFERENCE_COUNT: usize = 0x114; // ULONG
        pub const DEPENDENT_LOAD_FLAGS: usize = 0x118; // ULONG
        pub const SIGNING_LEVEL: usize = 0x11c; // UCHAR
        // Total size: 0x120
    }

    /// x64 Win11 24H2 (0x138) — adds CheckSum, ActivePatchImageBase, HotPatchState.
    pub mod x64_win11 {
        pub use super::x64_win10::*;
        // LoadContext replaces SnapContext at the same offset.
        pub const LOAD_CONTEXT: usize = 0xb0; // _LDRP_LOAD_CONTEXT*
        pub const CHECK_SUM: usize = 0x120; // ULONG
        pub const ACTIVE_PATCH_IMAGE_BASE: usize = 0x128; // VOID*
        pub const HOT_PATCH_STATE: usize = 0x130; // enum _LDR_HOT_PATCH_STATE
        // Total size: 0x138
    }

    // -------------------------------------------------------------------------
    // x86 — fields stable across Win7 → Win10
    // -------------------------------------------------------------------------
    mod common_x86 {
        pub const IN_LOAD_ORDER_LINKS: usize = 0x00; // _LIST_ENTRY (8 bytes)
        pub const IN_MEMORY_ORDER_LINKS: usize = 0x08; // _LIST_ENTRY
        pub const IN_INIT_ORDER_LINKS: usize = 0x10; // _LIST_ENTRY
        pub const DLL_BASE: usize = 0x18; // VOID* (4 bytes)
        pub const ENTRY_POINT: usize = 0x1c; // VOID*
        pub const SIZE_OF_IMAGE: usize = 0x20; // ULONG
        pub const FULL_DLL_NAME: usize = 0x24; // _UNICODE_STRING (8 bytes)
        pub const BASE_DLL_NAME: usize = 0x2c; // _UNICODE_STRING
        pub const FLAGS: usize = 0x34; // ULONG
        pub const OBSOLETE_LOAD_COUNT: usize = 0x38; // USHORT
        pub const TLS_INDEX: usize = 0x3a; // USHORT
        pub const HASH_LINKS: usize = 0x3c; // _LIST_ENTRY
        pub const TIME_DATE_STAMP: usize = 0x44; // ULONG
    }

    /// x86 Win7 (0x78) — legacy layout.
    pub mod x86_win7 {
        pub use super::common_x86::*;
        pub const ENTRY_POINT_ACTIVATION_CONTEXT: usize = 0x48;
        pub const PATCH_INFORMATION: usize = 0x4c;
        pub const FORWARDER_LINKS: usize = 0x50;
        pub const SERVICE_TAG_LINKS: usize = 0x58;
        pub const STATIC_LINKS: usize = 0x60;
        pub const CONTEXT_INFORMATION: usize = 0x68;
        pub const ORIGINAL_BASE: usize = 0x6c; // ULONG (x86)
        pub const LOAD_TIME: usize = 0x70; // _LARGE_INTEGER
        // Total size: 0x78
    }

    /// x86 Win10 22H2 (0xa8) — modern layout with DdagNode tree.
    pub mod x86_win10 {
        pub use super::common_x86::*;
        pub const ENTRY_POINT_ACTIVATION_CONTEXT: usize = 0x48;
        pub const LOCK: usize = 0x4c;
        pub const DDAG_NODE: usize = 0x50;
        pub const NODE_MODULE_LINK: usize = 0x54;
        pub const LOAD_CONTEXT: usize = 0x5c;
        pub const PARENT_DLL_BASE: usize = 0x60;
        pub const SWITCH_BACK_CONTEXT: usize = 0x64;
        pub const BASE_ADDRESS_INDEX_NODE: usize = 0x68;
        pub const MAPPING_INFO_INDEX_NODE: usize = 0x74;
        pub const ORIGINAL_BASE: usize = 0x80; // ULONG
        pub const LOAD_TIME: usize = 0x88;
        pub const BASE_NAME_HASH_VALUE: usize = 0x90;
        pub const LOAD_REASON: usize = 0x94;
        pub const IMPLICIT_PATH_OPTIONS: usize = 0x98;
        pub const REFERENCE_COUNT: usize = 0x9c;
        pub const DEPENDENT_LOAD_FLAGS: usize = 0xa0;
        pub const SIGNING_LEVEL: usize = 0xa4;
        // Total size: 0xa8
    }
}

/// Raw view into a `_LDR_DATA_TABLE_ENTRY`.
///
/// Obtain `ptr` via `ListEntry::containing_record` with the appropriate
/// `IN_LOAD_ORDER_LINKS` offset (0x0 on both x64 and x86).
pub struct LdrDataTableEntry {
    pub ptr: *const u8,
}

impl LdrDataTableEntry {
    pub unsafe fn new(ptr: *const u8) -> Self {
        Self { ptr }
    }

    pub unsafe fn dll_base(&self) -> *const u8 {
        unsafe { read_ptr(self.ptr, Self::off().dll_base) }
    }

    pub unsafe fn entry_point(&self) -> *const u8 {
        unsafe { read_ptr(self.ptr, Self::off().entry_point) }
    }

    pub unsafe fn size_of_image(&self) -> u32 {
        unsafe { read_u32(self.ptr, Self::off().size_of_image) }
    }

    pub unsafe fn flags(&self) -> u32 {
        unsafe { read_u32(self.ptr, Self::off().flags) }
    }

    pub unsafe fn time_date_stamp(&self) -> u32 {
        unsafe { read_u32(self.ptr, Self::off().time_date_stamp) }
    }

    pub unsafe fn full_dll_name(&self) -> Option<String> {
        unsafe { read_unicode_string(self.ptr, Self::off().full_dll_name) }
    }

    pub unsafe fn base_dll_name(&self) -> Option<String> {
        unsafe { read_unicode_string(self.ptr, Self::off().base_dll_name) }
    }

    // Compile-time offset selection — uses Win10/Win11 layout (most common).
    // For older OS targets swap the inner module below.
    #[cfg(target_arch = "x86_64")]
    fn off() -> Offsets {
        use offsets::x64_win10 as o;
        Offsets {
            dll_base: o::DLL_BASE,
            entry_point: o::ENTRY_POINT,
            size_of_image: o::SIZE_OF_IMAGE,
            full_dll_name: o::FULL_DLL_NAME,
            base_dll_name: o::BASE_DLL_NAME,
            flags: o::FLAGS,
            time_date_stamp: o::TIME_DATE_STAMP,
        }
    }

    #[cfg(target_arch = "x86")]
    fn off() -> Offsets {
        use offsets::x86_win10 as o;
        Offsets {
            dll_base: o::DLL_BASE,
            entry_point: o::ENTRY_POINT,
            size_of_image: o::SIZE_OF_IMAGE,
            full_dll_name: o::FULL_DLL_NAME,
            base_dll_name: o::BASE_DLL_NAME,
            flags: o::FLAGS,
            time_date_stamp: o::TIME_DATE_STAMP,
        }
    }
}

struct Offsets {
    dll_base: usize,
    entry_point: usize,
    size_of_image: usize,
    full_dll_name: usize,
    base_dll_name: usize,
    flags: usize,
    time_date_stamp: usize,
}
