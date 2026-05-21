/// Reads a null-terminated ASCII/UTF-8 string from `ptr`.
///
/// # Safety
/// `ptr` must point to a valid null-terminated UTF-8 or ASCII string in memory.
pub unsafe fn read_cstr(ptr: *const u8) -> String {
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = core::slice::from_raw_parts(ptr, len);
        String::from_utf8_lossy(slice).into_owned()
    }
}
