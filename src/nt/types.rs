#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::c_void;

pub type HANDLE = *mut c_void;
pub type SIZE_T = usize;

pub type ULONG = u32;
pub type LONG = i32;
pub type USHORT = u16;
pub type UCHAR = u8;
pub type CHAR = i8;
pub type BOOLEAN = u8;
pub type PWSTR = *mut u16;

//Punteros
pub type PVOID = *mut c_void;
pub type PULONG = *mut u32;

//ERRORES NT
pub const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820; // 0xC0000004 en i32

// Access rights mask (DWORD)
pub type ACCESS_MASK = u32;

/**
 * The UNICODE_STRING structure is used to pass Unicode strings.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PWSTR,
}

impl Default for UNICODE_STRING {
    fn default() -> Self {
        Self {
            Length: 0,
            MaximumLength: 0,
            Buffer: std::ptr::null_mut(),
        }
    }
}

/**
 * The GENERIC_MAPPING structure defines the mapping of generic access rights
 * to specific and standard access rights for an object.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct GENERIC_MAPPING {
    pub GenericRead: ACCESS_MASK,
    pub GenericWrite: ACCESS_MASK,
    pub GenericExecute: ACCESS_MASK,
    pub GenericAll: ACCESS_MASK,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct LARGE_INTEGER_PARTS {
    pub LowPart: ULONG,
    pub HighPart: LONG,
}

/**
 * The LARGE_INTEGER union is used to represent a 64-bit signed integer value.
 */
#[repr(C)]
#[derive(Copy, Clone)]
pub union LARGE_INTEGER {
    pub u: LARGE_INTEGER_PARTS,
    pub QuadPart: i64,
}

impl Default for LARGE_INTEGER {
    fn default() -> Self {
        Self { QuadPart: 0 }
    }
}

impl std::fmt::Debug for LARGE_INTEGER {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LARGE_INTEGER({})", unsafe { self.QuadPart })
    }
}
