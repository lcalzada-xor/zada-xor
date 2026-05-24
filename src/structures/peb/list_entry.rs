use crate::utils::*;

// _LIST_ENTRY is identical across all Windows versions (Vista → Win11).
// Only pointer width differs between architectures:
//   x64: Flink=0x0, Blink=0x8, total 0x10
//   x86: Flink=0x0, Blink=0x4, total 0x08
//
// Source: https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_LIST_ENTRY

pub mod offsets {
    pub mod x64 {
        pub const FLINK: usize = 0x0; // _LIST_ENTRY*
        pub const BLINK: usize = 0x8; // _LIST_ENTRY*
        // Total size: 0x10
    }

    pub mod x86 {
        pub const FLINK: usize = 0x0; // _LIST_ENTRY*
        pub const BLINK: usize = 0x4; // _LIST_ENTRY*
        // Total size: 0x08
    }
}

/// Raw view into a `_LIST_ENTRY` node.
///
/// `ptr` must point to a valid `_LIST_ENTRY`.  All methods are unsafe
/// because they dereference raw memory.
pub struct ListEntry {
    pub ptr: *const u8,
}

impl ListEntry {
    pub unsafe fn new(ptr: *const u8) -> Self {
        Self { ptr }
    }

    /// Forward link — next node in the list.
    pub unsafe fn flink(&self) -> *const u8 {
        unsafe { read_ptr(self.ptr, Self::off_flink()) }
    }

    /// Backward link — previous node in the list.
    pub unsafe fn blink(&self) -> *const u8 {
        unsafe { read_ptr(self.ptr, Self::off_blink()) }
    }

    /// Returns `true` if this entry is the list head (circular, pointing to itself).
    pub unsafe fn is_empty(&self) -> bool {
        unsafe { self.flink() == self.ptr }
    }

    /// Recovers the parent struct pointer given the byte offset of this
    /// `_LIST_ENTRY` field within that struct (`CONTAINING_RECORD` macro equivalent).
    ///
    /// # Safety
    /// `field_offset` must be the correct offset of the `_LIST_ENTRY` field
    /// inside the parent struct, and `self.ptr` must be a valid node.
    pub unsafe fn containing_record(&self, field_offset: usize) -> *const u8 {
        unsafe { self.ptr.sub(field_offset) }
    }

    /// Returns an iterator that walks Flink from `head` and stops before
    /// returning to `head`.  The head itself is never yielded.
    ///
    /// # Safety
    /// `self.ptr` must be the list head of a valid circular `_LIST_ENTRY` chain.
    pub unsafe fn iter(&self) -> ListIter {
        ListIter {
            head: self.ptr,
            current: unsafe { self.flink() },
        }
    }

    /// Returns `true` if any node in the list satisfies `predicate`.
    ///
    /// # Safety
    /// Same requirements as `iter`.
    pub unsafe fn contains<F>(&self, predicate: F) -> bool
    where
        F: FnMut(*const u8) -> bool,
    {
        unsafe { self.iter() }.any(predicate)
    }

    /// Returns the first node satisfying `predicate`, or `null` if none.
    ///
    /// # Safety
    /// Same requirements as `iter`.
    pub unsafe fn find<F>(&self, mut predicate: F) -> *const u8
    where
        F: FnMut(*const u8) -> bool,
    {
        unsafe { self.iter() }
            .find(|&p| predicate(p))
            .unwrap_or(core::ptr::null())
    }

    /// Counts the number of nodes in the list (excluding the head).
    ///
    /// # Safety
    /// Same requirements as `iter`.
    pub unsafe fn len(&self) -> usize {
        unsafe { self.iter() }.count()
    }

    #[cfg(target_arch = "x86_64")]
    fn off_flink() -> usize {
        offsets::x64::FLINK
    }
    #[cfg(target_arch = "x86_64")]
    fn off_blink() -> usize {
        offsets::x64::BLINK
    }

    #[cfg(target_arch = "x86")]
    fn off_flink() -> usize {
        offsets::x86::FLINK
    }
    #[cfg(target_arch = "x86")]
    fn off_blink() -> usize {
        offsets::x86::BLINK
    }
}

/// Iterator over the nodes of a circular `_LIST_ENTRY` chain.
///
/// Yields raw pointers to each `_LIST_ENTRY` node, walking Flink, and stops
/// when it reaches the head again.
pub struct ListIter {
    head: *const u8,
    current: *const u8,
}

impl Iterator for ListIter {
    type Item = *const u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current == self.head || self.current.is_null() {
            return None;
        }
        let node = self.current;
        // SAFETY: caller guarantees a valid chain; we advance Flink.
        self.current = unsafe { read_ptr(node, ListEntry::off_flink()) };
        Some(node)
    }
}
