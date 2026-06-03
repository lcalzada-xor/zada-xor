use crate::structures::pe::constants::*;
use crate::utils::{read_u16, read_u32};

/// Holds verified offset information for a parsed PE image.
pub struct PeHeaderInfo {
    pub nt_headers_ptr: *const u8,
    pub optional_header_ptr: *const u8,
    pub magic: u16,
}

impl PeHeaderInfo {
    pub unsafe fn parse_headers(base: *const u8) -> Option<Self> {
        unsafe {
            let e_lfanew = read_u32(base, DOS_E_LFANEW) as usize;
            let nt_headers_ptr = base.add(e_lfanew);

            if read_u32(nt_headers_ptr, 0) != PE_SIGNATURE {
                return None;
            }

            let optional_header_ptr = nt_headers_ptr.add(NT_SIGNATURE_SIZE + FILE_HEADER_SIZE);
            let magic = read_u16(optional_header_ptr, OPTIONAL_HEADER_MAGIC);

            if magic != PE32_MAGIC && magic != PE32_PLUS_MAGIC {
                return None;
            }

            Some(Self {
                nt_headers_ptr,
                optional_header_ptr,
                magic,
            })
        }
    }

    pub fn export_directory_offset(&self) -> Option<usize> {
        match self.magic {
            PE32_MAGIC => Some(DATA_DIR_EXPORT_OFFSET_PE32),
            PE32_PLUS_MAGIC => Some(DATA_DIR_EXPORT_OFFSET_PE32_PLUS),
            _ => None,
        }
    }
}
