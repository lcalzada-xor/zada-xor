/// PEB field offsets for x86 (32-bit) Windows.
///
/// Source: https://www.vergiliusproject.com/kernels/x86
///
/// Register access:
///   FS:[0x30]  -> pointer to PEB (native x86 process)
///
/// Layout variants grouped by the first Windows version where they appear.
/// Fields shared across all versions are listed in the XP block and only
/// re-listed when their offset changes in a later release.

// ---------------------------------------------------------------------------
// Windows XP SP3  (5.1.2600.5512) — total size 0x210
// Source: /kernels/x86/windows-xp/sp3/_PEB
// ---------------------------------------------------------------------------
pub mod xp {
    pub const INHERITED_ADDRESS_SPACE: usize = 0x000; // UCHAR
    pub const READ_IMAGE_FILE_EXEC_OPTIONS: usize = 0x001; // UCHAR
    pub const BEING_DEBUGGED: usize = 0x002; // UCHAR
    /// XP uses a plain UCHAR (no named bitfield).
    pub const SPARE_BOOL: usize = 0x003; // UCHAR
    pub const MUTANT: usize = 0x004; // VOID*
    pub const IMAGE_BASE_ADDRESS: usize = 0x008; // VOID*
    pub const LDR: usize = 0x00C; // _PEB_LDR_DATA*
    pub const PROCESS_PARAMETERS: usize = 0x010; // _RTL_USER_PROCESS_PARAMETERS*
    pub const SUB_SYSTEM_DATA: usize = 0x014; // VOID*
    pub const PROCESS_HEAP: usize = 0x018; // VOID*
    pub const FAST_PEB_LOCK: usize = 0x01C; // _RTL_CRITICAL_SECTION*
    /// XP only — removed in Vista.
    pub const FAST_PEB_LOCK_ROUTINE: usize = 0x020; // VOID*
    /// XP only — removed in Vista.
    pub const FAST_PEB_UNLOCK_ROUTINE: usize = 0x024; // VOID*
    /// XP only — replaced by CrossProcessFlags in Vista.
    pub const ENVIRONMENT_UPDATE_COUNT: usize = 0x028; // ULONG
    pub const KERNEL_CALLBACK_TABLE: usize = 0x02C; // VOID*
    pub const SYSTEM_RESERVED: usize = 0x030; // ULONG[1]
    pub const ATL_THUNK_SLIST_PTR32: usize = 0x034; // ULONG
    /// XP only — replaced by ApiSetMap in Vista.
    pub const FREE_LIST: usize = 0x038; // _PEB_FREE_BLOCK*
    pub const TLS_EXPANSION_COUNTER: usize = 0x03C; // ULONG
    pub const TLS_BITMAP: usize = 0x040; // VOID*
    pub const TLS_BITMAP_BITS: usize = 0x044; // ULONG[2]
    pub const READ_ONLY_SHARED_MEMORY_BASE: usize = 0x04C; // VOID*
    /// XP name: ReadOnlySharedMemoryHeap. Renamed to SharedData/HotpatchInformation in Vista+.
    pub const READ_ONLY_SHARED_MEMORY_HEAP: usize = 0x050; // VOID*
    pub const READ_ONLY_STATIC_SERVER_DATA: usize = 0x054; // VOID**
    pub const ANSI_CODE_PAGE_DATA: usize = 0x058; // VOID*
    pub const OEM_CODE_PAGE_DATA: usize = 0x05C; // VOID*
    pub const UNICODE_CASE_TABLE_DATA: usize = 0x060; // VOID*
    pub const NUMBER_OF_PROCESSORS: usize = 0x064; // ULONG
    pub const NT_GLOBAL_FLAG: usize = 0x068; // ULONG
    pub const CRITICAL_SECTION_TIMEOUT: usize = 0x070; // _LARGE_INTEGER
    pub const HEAP_SEGMENT_RESERVE: usize = 0x078; // ULONG
    pub const HEAP_SEGMENT_COMMIT: usize = 0x07C; // ULONG
    pub const HEAP_DECOMMIT_TOTAL_FREE_THRESHOLD: usize = 0x080; // ULONG
    pub const HEAP_DECOMMIT_FREE_BLOCK_THRESHOLD: usize = 0x084; // ULONG
    pub const NUMBER_OF_HEAPS: usize = 0x088; // ULONG
    pub const MAXIMUM_NUMBER_OF_HEAPS: usize = 0x08C; // ULONG
    pub const PROCESS_HEAPS: usize = 0x090; // VOID**
    pub const GDI_SHARED_HANDLE_TABLE: usize = 0x094; // VOID*
    pub const PROCESS_STARTER_HELPER: usize = 0x098; // VOID*
    pub const GDI_DC_ATTRIBUTE_LIST: usize = 0x09C; // ULONG
    pub const LOADER_LOCK: usize = 0x0A0; // VOID* (plain in XP)
    pub const OS_MAJOR_VERSION: usize = 0x0A4; // ULONG
    pub const OS_MINOR_VERSION: usize = 0x0A8; // ULONG
    pub const OS_BUILD_NUMBER: usize = 0x0AC; // USHORT
    pub const OS_CSD_VERSION: usize = 0x0AE; // USHORT
    pub const OS_PLATFORM_ID: usize = 0x0B0; // ULONG
    pub const IMAGE_SUBSYSTEM: usize = 0x0B4; // ULONG
    pub const IMAGE_SUBSYSTEM_MAJOR_VERSION: usize = 0x0B8; // ULONG
    pub const IMAGE_SUBSYSTEM_MINOR_VERSION: usize = 0x0BC; // ULONG
    /// XP name: ImageProcessAffinityMask (ULONG, not ULONGLONG).
    pub const IMAGE_PROCESS_AFFINITY_MASK: usize = 0x0C0; // ULONG
    pub const GDI_HANDLE_BUFFER: usize = 0x0C4; // ULONG[34] — 136 bytes
    pub const POST_PROCESS_INIT_ROUTINE: usize = 0x14C; // VOID(*)(VOID)
    pub const TLS_EXPANSION_BITMAP: usize = 0x150; // VOID*
    pub const TLS_EXPANSION_BITMAP_BITS: usize = 0x154; // ULONG[32]
    pub const SESSION_ID: usize = 0x1D4; // ULONG
    pub const APP_COMPAT_FLAGS: usize = 0x1D8; // _ULARGE_INTEGER
    pub const APP_COMPAT_FLAGS_USER: usize = 0x1E0; // _ULARGE_INTEGER
    pub const P_SHIM_DATA: usize = 0x1E8; // VOID*
    pub const APP_COMPAT_INFO: usize = 0x1EC; // VOID*
    pub const CSD_VERSION: usize = 0x1F0; // _UNICODE_STRING (8 bytes on x86)
    pub const ACTIVATION_CONTEXT_DATA: usize = 0x1F8; // VOID*
    pub const PROCESS_ASSEMBLY_STORAGE_MAP: usize = 0x1FC; // VOID*
    pub const SYSTEM_DEFAULT_ACTIVATION_CONTEXT_DATA: usize = 0x200; // VOID*
    pub const SYSTEM_ASSEMBLY_STORAGE_MAP: usize = 0x204; // VOID*
    pub const MINIMUM_STACK_COMMIT: usize = 0x208; // ULONG
    // Total size: 0x210
}

// ---------------------------------------------------------------------------
// Windows Vista / Server 2008 SP2 (x86) — changes relative to XP
// (No dedicated Vergilius page for Vista x86; offsets inferred from Vista x64
//  pattern-shift and public WinDBG dt output.)
//
// Key changes from XP:
//   0x003  SpareBool → BitField (named bitfield, same offset)
//   0x020  FastPebLockRoutine removed
//   0x024  FastPebUnlockRoutine removed
//   0x028  EnvironmentUpdateCount → CrossProcessFlags (union)
//   0x02C  KernelCallbackTable/UserSharedInfoPtr (union)
//   0x038  FreeList → ApiSetMap
//   0x050  ReadOnlySharedMemoryHeap → HotpatchInformation
//   After MinimumStackCommit, FLS fields added (see below)
// ---------------------------------------------------------------------------
pub mod vista {
    pub const INHERITED_ADDRESS_SPACE: usize = 0x000;
    pub const READ_IMAGE_FILE_EXEC_OPTIONS: usize = 0x001;
    pub const BEING_DEBUGGED: usize = 0x002;
    pub const BIT_FIELD: usize = 0x003; // UCHAR (bitfield union)
    pub const MUTANT: usize = 0x004;
    pub const IMAGE_BASE_ADDRESS: usize = 0x008;
    pub const LDR: usize = 0x00C;
    pub const PROCESS_PARAMETERS: usize = 0x010;
    pub const SUB_SYSTEM_DATA: usize = 0x014;
    pub const PROCESS_HEAP: usize = 0x018;
    pub const FAST_PEB_LOCK: usize = 0x01C;
    pub const ATL_THUNK_SLIST_PTR: usize = 0x020; // VOID* (was FastPebLockRoutine slot)
    pub const IFEO_KEY: usize = 0x024; // VOID*
    pub const CROSS_PROCESS_FLAGS: usize = 0x028; // ULONG (union)
    pub const KERNEL_CALLBACK_TABLE: usize = 0x02C; // VOID* (union with UserSharedInfoPtr)
    pub const SYSTEM_RESERVED: usize = 0x030;
    pub const ATL_THUNK_SLIST_PTR32: usize = 0x034;
    pub const API_SET_MAP: usize = 0x038; // VOID* (was FreeList)
    pub const TLS_EXPANSION_COUNTER: usize = 0x03C;
    pub const TLS_BITMAP: usize = 0x040;
    pub const TLS_BITMAP_BITS: usize = 0x044;
    pub const READ_ONLY_SHARED_MEMORY_BASE: usize = 0x04C;
    pub const HOTPATCH_INFORMATION: usize = 0x050; // VOID* (was ReadOnlySharedMemoryHeap)
    pub const READ_ONLY_STATIC_SERVER_DATA: usize = 0x054;
    pub const ANSI_CODE_PAGE_DATA: usize = 0x058;
    pub const OEM_CODE_PAGE_DATA: usize = 0x05C;
    pub const UNICODE_CASE_TABLE_DATA: usize = 0x060;
    pub const NUMBER_OF_PROCESSORS: usize = 0x064;
    pub const NT_GLOBAL_FLAG: usize = 0x068;
    pub const CRITICAL_SECTION_TIMEOUT: usize = 0x070;
    pub const HEAP_SEGMENT_RESERVE: usize = 0x078;
    pub const HEAP_SEGMENT_COMMIT: usize = 0x07C;
    pub const HEAP_DECOMMIT_TOTAL_FREE_THRESHOLD: usize = 0x080;
    pub const HEAP_DECOMMIT_FREE_BLOCK_THRESHOLD: usize = 0x084;
    pub const NUMBER_OF_HEAPS: usize = 0x088;
    pub const MAXIMUM_NUMBER_OF_HEAPS: usize = 0x08C;
    pub const PROCESS_HEAPS: usize = 0x090;
    pub const GDI_SHARED_HANDLE_TABLE: usize = 0x094;
    pub const PROCESS_STARTER_HELPER: usize = 0x098;
    pub const GDI_DC_ATTRIBUTE_LIST: usize = 0x09C;
    pub const LOADER_LOCK: usize = 0x0A0; // _RTL_CRITICAL_SECTION*
    pub const OS_MAJOR_VERSION: usize = 0x0A4;
    pub const OS_MINOR_VERSION: usize = 0x0A8;
    pub const OS_BUILD_NUMBER: usize = 0x0AC;
    pub const OS_CSD_VERSION: usize = 0x0AE;
    pub const OS_PLATFORM_ID: usize = 0x0B0;
    pub const IMAGE_SUBSYSTEM: usize = 0x0B4;
    pub const IMAGE_SUBSYSTEM_MAJOR_VERSION: usize = 0x0B8;
    pub const IMAGE_SUBSYSTEM_MINOR_VERSION: usize = 0x0BC;
    pub const ACTIVE_PROCESS_AFFINITY_MASK: usize = 0x0C0; // ULONG
    pub const GDI_HANDLE_BUFFER: usize = 0x0C4; // ULONG[34]
    pub const POST_PROCESS_INIT_ROUTINE: usize = 0x14C;
    pub const TLS_EXPANSION_BITMAP: usize = 0x150;
    pub const TLS_EXPANSION_BITMAP_BITS: usize = 0x154;
    pub const SESSION_ID: usize = 0x1D4;
    pub const APP_COMPAT_FLAGS: usize = 0x1D8;
    pub const APP_COMPAT_FLAGS_USER: usize = 0x1E0;
    pub const P_SHIM_DATA: usize = 0x1E8;
    pub const APP_COMPAT_INFO: usize = 0x1EC;
    pub const CSD_VERSION: usize = 0x1F0;
    pub const ACTIVATION_CONTEXT_DATA: usize = 0x1F8;
    pub const PROCESS_ASSEMBLY_STORAGE_MAP: usize = 0x1FC;
    pub const SYSTEM_DEFAULT_ACTIVATION_CONTEXT_DATA: usize = 0x200;
    pub const SYSTEM_ASSEMBLY_STORAGE_MAP: usize = 0x204;
    pub const MINIMUM_STACK_COMMIT: usize = 0x208;
    // FLS fields — new in Vista
    pub const FLS_CALLBACK: usize = 0x20C; // _FLS_CALLBACK_INFO*
    pub const FLS_LIST_HEAD: usize = 0x210; // _LIST_ENTRY (8 bytes)
    pub const FLS_BITMAP: usize = 0x218; // VOID*
    pub const FLS_BITMAP_BITS: usize = 0x21C; // ULONG[4]
    pub const FLS_HIGH_INDEX: usize = 0x22C; // ULONG
    pub const WER_REGISTRATION_DATA: usize = 0x230; // VOID*
    pub const WER_SHIP_ASSERT_PTR: usize = 0x234; // VOID*
    // Total size: ~0x23C
}

// ---------------------------------------------------------------------------
// Windows 7 SP1  (6.1.7601.17514, x86) — total size 0x248
// Source: /kernels/x86/windows-7/sp1/_PEB
// Identical layout to Vista x86 through WerShipAssertPtr, then adds:
// ---------------------------------------------------------------------------
pub mod win7 {
    // Re-export Vista offsets that did not change.
    pub use super::vista::{
        ACTIVATION_CONTEXT_DATA, ACTIVE_PROCESS_AFFINITY_MASK, ANSI_CODE_PAGE_DATA, API_SET_MAP,
        APP_COMPAT_FLAGS, APP_COMPAT_FLAGS_USER, APP_COMPAT_INFO, ATL_THUNK_SLIST_PTR,
        ATL_THUNK_SLIST_PTR32, BEING_DEBUGGED, BIT_FIELD, CRITICAL_SECTION_TIMEOUT,
        CROSS_PROCESS_FLAGS, CSD_VERSION, FAST_PEB_LOCK, FLS_BITMAP, FLS_BITMAP_BITS, FLS_CALLBACK,
        FLS_HIGH_INDEX, FLS_LIST_HEAD, GDI_DC_ATTRIBUTE_LIST, GDI_HANDLE_BUFFER,
        GDI_SHARED_HANDLE_TABLE, HEAP_DECOMMIT_FREE_BLOCK_THRESHOLD,
        HEAP_DECOMMIT_TOTAL_FREE_THRESHOLD, HEAP_SEGMENT_COMMIT, HEAP_SEGMENT_RESERVE,
        HOTPATCH_INFORMATION, IFEO_KEY, IMAGE_BASE_ADDRESS, IMAGE_SUBSYSTEM,
        IMAGE_SUBSYSTEM_MAJOR_VERSION, IMAGE_SUBSYSTEM_MINOR_VERSION, INHERITED_ADDRESS_SPACE,
        KERNEL_CALLBACK_TABLE, LDR, LOADER_LOCK, MAXIMUM_NUMBER_OF_HEAPS, MINIMUM_STACK_COMMIT,
        MUTANT, NT_GLOBAL_FLAG, NUMBER_OF_HEAPS, NUMBER_OF_PROCESSORS, OEM_CODE_PAGE_DATA,
        OS_BUILD_NUMBER, OS_CSD_VERSION, OS_MAJOR_VERSION, OS_MINOR_VERSION, OS_PLATFORM_ID,
        P_SHIM_DATA, POST_PROCESS_INIT_ROUTINE, PROCESS_ASSEMBLY_STORAGE_MAP, PROCESS_HEAP,
        PROCESS_HEAPS, PROCESS_PARAMETERS, PROCESS_STARTER_HELPER, READ_IMAGE_FILE_EXEC_OPTIONS,
        READ_ONLY_SHARED_MEMORY_BASE, READ_ONLY_STATIC_SERVER_DATA, SESSION_ID, SUB_SYSTEM_DATA,
        SYSTEM_ASSEMBLY_STORAGE_MAP, SYSTEM_DEFAULT_ACTIVATION_CONTEXT_DATA, SYSTEM_RESERVED,
        TLS_BITMAP, TLS_BITMAP_BITS, TLS_EXPANSION_BITMAP, TLS_EXPANSION_BITMAP_BITS,
        TLS_EXPANSION_COUNTER, UNICODE_CASE_TABLE_DATA, WER_REGISTRATION_DATA, WER_SHIP_ASSERT_PTR,
    };
    // New in Win7 x86
    pub const P_CONTEXT_DATA: usize = 0x238; // VOID* (pContextData)
    pub const P_IMAGE_HEADER_HASH: usize = 0x23C; // VOID*
    pub const TRACING_FLAGS: usize = 0x240; // ULONG (union)
    // Total size: 0x248
}

// ---------------------------------------------------------------------------
// Windows 8 / Server 2012 (x86) — changes relative to Win7
// (Offsets verified against public WinDBG dt output for 6.2.9200)
//
// Key changes:
//   0x238  pContextData → pUnused
//   0x240  TracingFlags stays
//   0x244  CsrServerReadOnlySharedMemoryBase added (ULONGLONG — 8 bytes on x86)
// ---------------------------------------------------------------------------
pub mod win8 {
    pub use super::win7::{
        ACTIVATION_CONTEXT_DATA, ACTIVE_PROCESS_AFFINITY_MASK, ANSI_CODE_PAGE_DATA, API_SET_MAP,
        APP_COMPAT_FLAGS, APP_COMPAT_FLAGS_USER, APP_COMPAT_INFO, ATL_THUNK_SLIST_PTR,
        ATL_THUNK_SLIST_PTR32, BEING_DEBUGGED, BIT_FIELD, CRITICAL_SECTION_TIMEOUT,
        CROSS_PROCESS_FLAGS, CSD_VERSION, FAST_PEB_LOCK, FLS_BITMAP, FLS_BITMAP_BITS, FLS_CALLBACK,
        FLS_HIGH_INDEX, FLS_LIST_HEAD, GDI_DC_ATTRIBUTE_LIST, GDI_HANDLE_BUFFER,
        GDI_SHARED_HANDLE_TABLE, HEAP_DECOMMIT_FREE_BLOCK_THRESHOLD,
        HEAP_DECOMMIT_TOTAL_FREE_THRESHOLD, HEAP_SEGMENT_COMMIT, HEAP_SEGMENT_RESERVE,
        HOTPATCH_INFORMATION, IFEO_KEY, IMAGE_BASE_ADDRESS, IMAGE_SUBSYSTEM,
        IMAGE_SUBSYSTEM_MAJOR_VERSION, IMAGE_SUBSYSTEM_MINOR_VERSION, INHERITED_ADDRESS_SPACE,
        KERNEL_CALLBACK_TABLE, LDR, LOADER_LOCK, MAXIMUM_NUMBER_OF_HEAPS, MINIMUM_STACK_COMMIT,
        MUTANT, NT_GLOBAL_FLAG, NUMBER_OF_HEAPS, NUMBER_OF_PROCESSORS, OEM_CODE_PAGE_DATA,
        OS_BUILD_NUMBER, OS_CSD_VERSION, OS_MAJOR_VERSION, OS_MINOR_VERSION, OS_PLATFORM_ID,
        P_IMAGE_HEADER_HASH, P_SHIM_DATA, POST_PROCESS_INIT_ROUTINE, PROCESS_ASSEMBLY_STORAGE_MAP,
        PROCESS_HEAP, PROCESS_HEAPS, PROCESS_PARAMETERS, PROCESS_STARTER_HELPER,
        READ_IMAGE_FILE_EXEC_OPTIONS, READ_ONLY_SHARED_MEMORY_BASE, READ_ONLY_STATIC_SERVER_DATA,
        SESSION_ID, SUB_SYSTEM_DATA, SYSTEM_ASSEMBLY_STORAGE_MAP,
        SYSTEM_DEFAULT_ACTIVATION_CONTEXT_DATA, SYSTEM_RESERVED, TLS_BITMAP, TLS_BITMAP_BITS,
        TLS_EXPANSION_BITMAP, TLS_EXPANSION_BITMAP_BITS, TLS_EXPANSION_COUNTER, TRACING_FLAGS,
        UNICODE_CASE_TABLE_DATA, WER_REGISTRATION_DATA, WER_SHIP_ASSERT_PTR,
    };
    pub const P_UNUSED: usize = 0x238; // VOID* (was pContextData)
    pub const CSR_SERVER_READ_ONLY_SHARED_MEMORY_BASE: usize = 0x244; // ULONGLONG
}

// ---------------------------------------------------------------------------
// Windows 10 22H2  (10.0.19045.2965, x86) — total size 0x480
// Source: /kernels/x86/windows-10/22h2/_PEB
//
// Key changes from Win8:
//   FLS fields removed; replaced by SparePointers/SpareUlongs padding.
//   SharedData field renamed back, WaitOnAddressHashTable added (128 pointers).
//   New fields: TelemetryCoverageHeader, CloudFileFlags, LeapSecondData, NtGlobalFlag2.
// ---------------------------------------------------------------------------
pub mod win10 {
    pub const INHERITED_ADDRESS_SPACE: usize = 0x000;
    pub const READ_IMAGE_FILE_EXEC_OPTIONS: usize = 0x001;
    pub const BEING_DEBUGGED: usize = 0x002;
    pub const BIT_FIELD: usize = 0x003;
    pub const MUTANT: usize = 0x004;
    pub const IMAGE_BASE_ADDRESS: usize = 0x008;
    pub const LDR: usize = 0x00C;
    pub const PROCESS_PARAMETERS: usize = 0x010;
    pub const SUB_SYSTEM_DATA: usize = 0x014;
    pub const PROCESS_HEAP: usize = 0x018;
    pub const FAST_PEB_LOCK: usize = 0x01C;
    pub const ATL_THUNK_SLIST_PTR: usize = 0x020;
    pub const IFEO_KEY: usize = 0x024;
    pub const CROSS_PROCESS_FLAGS: usize = 0x028;
    pub const KERNEL_CALLBACK_TABLE: usize = 0x02C;
    pub const SYSTEM_RESERVED: usize = 0x030;
    pub const ATL_THUNK_SLIST_PTR32: usize = 0x034;
    pub const API_SET_MAP: usize = 0x038;
    pub const TLS_EXPANSION_COUNTER: usize = 0x03C;
    pub const TLS_BITMAP: usize = 0x040;
    pub const TLS_BITMAP_BITS: usize = 0x044;
    pub const READ_ONLY_SHARED_MEMORY_BASE: usize = 0x04C;
    pub const SHARED_DATA: usize = 0x050; // VOID* (was HotpatchInformation)
    pub const READ_ONLY_STATIC_SERVER_DATA: usize = 0x054;
    pub const ANSI_CODE_PAGE_DATA: usize = 0x058;
    pub const OEM_CODE_PAGE_DATA: usize = 0x05C;
    pub const UNICODE_CASE_TABLE_DATA: usize = 0x060;
    pub const NUMBER_OF_PROCESSORS: usize = 0x064;
    pub const NT_GLOBAL_FLAG: usize = 0x068;
    pub const CRITICAL_SECTION_TIMEOUT: usize = 0x070;
    pub const HEAP_SEGMENT_RESERVE: usize = 0x078;
    pub const HEAP_SEGMENT_COMMIT: usize = 0x07C;
    pub const HEAP_DECOMMIT_TOTAL_FREE_THRESHOLD: usize = 0x080;
    pub const HEAP_DECOMMIT_FREE_BLOCK_THRESHOLD: usize = 0x084;
    pub const NUMBER_OF_HEAPS: usize = 0x088;
    pub const MAXIMUM_NUMBER_OF_HEAPS: usize = 0x08C;
    pub const PROCESS_HEAPS: usize = 0x090;
    pub const GDI_SHARED_HANDLE_TABLE: usize = 0x094;
    pub const PROCESS_STARTER_HELPER: usize = 0x098;
    pub const GDI_DC_ATTRIBUTE_LIST: usize = 0x09C;
    pub const LOADER_LOCK: usize = 0x0A0;
    pub const OS_MAJOR_VERSION: usize = 0x0A4;
    pub const OS_MINOR_VERSION: usize = 0x0A8;
    pub const OS_BUILD_NUMBER: usize = 0x0AC;
    pub const OS_CSD_VERSION: usize = 0x0AE;
    pub const OS_PLATFORM_ID: usize = 0x0B0;
    pub const IMAGE_SUBSYSTEM: usize = 0x0B4;
    pub const IMAGE_SUBSYSTEM_MAJOR_VERSION: usize = 0x0B8;
    pub const IMAGE_SUBSYSTEM_MINOR_VERSION: usize = 0x0BC;
    pub const ACTIVE_PROCESS_AFFINITY_MASK: usize = 0x0C0;
    pub const GDI_HANDLE_BUFFER: usize = 0x0C4; // ULONG[34]
    pub const POST_PROCESS_INIT_ROUTINE: usize = 0x14C;
    pub const TLS_EXPANSION_BITMAP: usize = 0x150;
    pub const TLS_EXPANSION_BITMAP_BITS: usize = 0x154;
    pub const SESSION_ID: usize = 0x1D4;
    pub const APP_COMPAT_FLAGS: usize = 0x1D8;
    pub const APP_COMPAT_FLAGS_USER: usize = 0x1E0;
    pub const P_SHIM_DATA: usize = 0x1E8;
    pub const APP_COMPAT_INFO: usize = 0x1EC;
    pub const CSD_VERSION: usize = 0x1F0;
    pub const ACTIVATION_CONTEXT_DATA: usize = 0x1F8;
    pub const PROCESS_ASSEMBLY_STORAGE_MAP: usize = 0x1FC;
    pub const SYSTEM_DEFAULT_ACTIVATION_CONTEXT_DATA: usize = 0x200;
    pub const SYSTEM_ASSEMBLY_STORAGE_MAP: usize = 0x204;
    pub const MINIMUM_STACK_COMMIT: usize = 0x208;
    /// SparePointers[4] — padding replacing FLS fields.
    pub const SPARE_POINTERS: usize = 0x20C; // VOID*[4]
    /// SpareUlongs[5] — padding.
    pub const SPARE_ULONGS: usize = 0x21C; // ULONG[5]
    pub const WER_REGISTRATION_DATA: usize = 0x230;
    pub const WER_SHIP_ASSERT_PTR: usize = 0x234;
    pub const P_UNUSED: usize = 0x238;
    pub const P_IMAGE_HEADER_HASH: usize = 0x23C;
    pub const TRACING_FLAGS: usize = 0x240;
    /// ULONGLONG stored at 4-byte-aligned address on x86.
    pub const CSR_SERVER_READ_ONLY_SHARED_MEMORY_BASE: usize = 0x248;
    pub const TPP_WORKER_P_LIST_LOCK: usize = 0x250; // ULONG
    pub const TPP_WORKER_P_LIST: usize = 0x254; // _LIST_ENTRY
    /// VOID*[128] — 0x200 bytes.
    pub const WAIT_ON_ADDRESS_HASH_TABLE: usize = 0x25C;
    pub const TELEMETRY_COVERAGE_HEADER: usize = 0x45C;
    pub const CLOUD_FILE_FLAGS: usize = 0x460;
    pub const CLOUD_FILE_DIAG_FLAGS: usize = 0x464;
    pub const PLACEHOLDER_COMPATIBILITY_MODE: usize = 0x468; // CHAR
    pub const PLACEHOLDER_COMPATIBILITY_MODE_RESERVED: usize = 0x469; // CHAR[7]
    pub const LEAP_SECOND_DATA: usize = 0x470; // _LEAP_SECOND_DATA*
    pub const LEAP_SECOND_FLAGS: usize = 0x474; // ULONG
    pub const NT_GLOBAL_FLAG2: usize = 0x478; // ULONG
    // Total size: 0x480
}
