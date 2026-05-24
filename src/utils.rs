pub unsafe fn read_u8(base: *const u8, offset: usize) -> u8 {
    unsafe { base.add(offset).read_unaligned() }
}

pub unsafe fn read_u16(base: *const u8, offset: usize) -> u16 {
    unsafe { base.add(offset).cast::<u16>().read_unaligned() }
}

pub unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    unsafe { base.add(offset).cast::<u32>().read_unaligned() }
}

pub unsafe fn read_ptr(base: *const u8, offset: usize) -> *const u8 {
    unsafe { base.add(offset).cast::<*const u8>().read_unaligned() }
}

#[cfg(target_arch = "x86_64")]
const UNICODE_STRING_BUFFER_OFF: usize = 0x8;
#[cfg(target_arch = "x86")]
const UNICODE_STRING_BUFFER_OFF: usize = 0x4;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u16,
}

impl UnicodeString {
    pub fn new(base: *const u8, offset: usize) -> Option<Self> {
        unsafe {
            let us = base.add(offset);
            let length = read_u16(us, 0x0);
            if length == 0 {
                return None;
            }
            let buffer = read_ptr(us, UNICODE_STRING_BUFFER_OFF);
            if buffer.is_null() {
                return None;
            }
            Some(Self {
                length,
                maximum_length: read_u16(us, 0x2),
                buffer: buffer.cast::<u16>(),
            })
        }
    }

    pub fn to_string(&self) -> String {
        if self.buffer.is_null() || self.length == 0 {
            return String::new();
        }
        unsafe {
            let char_count = self.length as usize / 2;
            let slice = core::slice::from_raw_parts(self.buffer, char_count);
            String::from_utf16_lossy(slice)
        }
    }
}

pub unsafe fn read_unicode_string(base: *const u8, offset: usize) -> Option<String> {
    UnicodeString::new(base, offset).map(|us| us.to_string())
}
