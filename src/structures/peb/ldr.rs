use crate::utils::*;

pub mod offsets {
    /// x64: _PEB_LDR_DATA field offsets (total size 0x58)
    pub mod x64 {
        pub const LENGTH: usize = 0x00; // ULONG
        pub const INITIALIZED: usize = 0x04; // UCHAR
        // 0x05-0x07: implicit padding
        pub const SS_HANDLE: usize = 0x08; // VOID*
        pub const IN_LOAD_ORDER_MODULE_LIST: usize = 0x10; // _LIST_ENTRY (Flink=0x10, Blink=0x18)
        pub const IN_MEMORY_ORDER_MODULE_LIST: usize = 0x20; // _LIST_ENTRY (Flink=0x20, Blink=0x28)
        pub const IN_INITIALIZATION_ORDER_MODULE_LIST: usize = 0x30; // _LIST_ENTRY (Flink=0x30, Blink=0x38)
        pub const ENTRY_IN_PROGRESS: usize = 0x40; // VOID*
        pub const SHUTDOWN_IN_PROGRESS: usize = 0x48; // UCHAR
        // 0x49-0x4F: implicit padding
        pub const SHUTDOWN_THREAD_ID: usize = 0x50; // VOID*
        // Total size: 0x58
    }

    /// x86: _PEB_LDR_DATA field offsets (total size 0x30)
    pub mod x86 {
        pub const LENGTH: usize = 0x00; // ULONG
        pub const INITIALIZED: usize = 0x04; // UCHAR
        // 0x05-0x07: implicit padding
        pub const SS_HANDLE: usize = 0x08; // VOID* (4 bytes)
        pub const IN_LOAD_ORDER_MODULE_LIST: usize = 0x0C; // _LIST_ENTRY (Flink=0x0C, Blink=0x10)
        pub const IN_MEMORY_ORDER_MODULE_LIST: usize = 0x14; // _LIST_ENTRY (Flink=0x14, Blink=0x18)
        pub const IN_INITIALIZATION_ORDER_MODULE_LIST: usize = 0x1C; // _LIST_ENTRY (Flink=0x1C, Blink=0x20)
        pub const ENTRY_IN_PROGRESS: usize = 0x24; // VOID* (4 bytes)
        pub const SHUTDOWN_IN_PROGRESS: usize = 0x28; // UCHAR
        // 0x29-0x2B: implicit padding
        pub const SHUTDOWN_THREAD_ID: usize = 0x2C; // VOID* (4 bytes)
        // Total size: 0x30
    }
}

pub struct PebLdrData {
    pub ptr: *const u8,
}

impl PebLdrData {
    pub unsafe fn from_ptr(ptr: *const u8) -> Self {
        Self { ptr }
    }

    /// Returns `true` once the loader has finished initializing.
    pub unsafe fn initialized(&self) -> bool {
        unsafe { self.read_u8(Self::off_initialized()) != 0 }
    }

    /// `Flink` of `InLoadOrderModuleList` — head of the load-order list.
    pub unsafe fn in_load_order_flink(&self) -> *const u8 {
        unsafe { self.read_ptr(Self::off_in_load_order()) }
    }

    /// `Flink` of `InMemoryOrderModuleList` — head of the memory-order list.
    pub unsafe fn in_memory_order_flink(&self) -> *const u8 {
        unsafe { self.read_ptr(Self::off_in_memory_order()) }
    }

    /// `Flink` of `InInitializationOrderModuleList`.
    pub unsafe fn in_init_order_flink(&self) -> *const u8 {
        unsafe { self.read_ptr(Self::off_in_init_order()) }
    }

    // --- offset helpers (selected at compile time) ---------------------------

    #[cfg(target_arch = "x86_64")]
    fn off_initialized() -> usize {
        offsets::x64::INITIALIZED
    }
    #[cfg(target_arch = "x86_64")]
    fn off_in_load_order() -> usize {
        offsets::x64::IN_LOAD_ORDER_MODULE_LIST
    }
    #[cfg(target_arch = "x86_64")]
    fn off_in_memory_order() -> usize {
        offsets::x64::IN_MEMORY_ORDER_MODULE_LIST
    }
    #[cfg(target_arch = "x86_64")]
    fn off_in_init_order() -> usize {
        offsets::x64::IN_INITIALIZATION_ORDER_MODULE_LIST
    }

    #[cfg(target_arch = "x86")]
    fn off_initialized() -> usize {
        offsets::x86::INITIALIZED
    }
    #[cfg(target_arch = "x86")]
    fn off_in_load_order() -> usize {
        offsets::x86::IN_LOAD_ORDER_MODULE_LIST
    }
    #[cfg(target_arch = "x86")]
    fn off_in_memory_order() -> usize {
        offsets::x86::IN_MEMORY_ORDER_MODULE_LIST
    }
    #[cfg(target_arch = "x86")]
    fn off_in_init_order() -> usize {
        offsets::x86::IN_INITIALIZATION_ORDER_MODULE_LIST
    }

    // --- raw read wrappers ---------------------------------------------------

    unsafe fn read_u8(&self, offset: usize) -> u8 {
        unsafe { read_u8(self.ptr, offset) }
    }

    unsafe fn read_ptr(&self, offset: usize) -> *const u8 {
        unsafe { read_ptr(self.ptr, offset) }
    }
}
