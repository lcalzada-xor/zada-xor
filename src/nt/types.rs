#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::c_void;

pub type HANDLE = *mut c_void;
pub type SIZE_T = usize;

pub type UINT8 = u8;
pub type ULONG = u32; //32b
pub type ULONGLONG = u64;
pub type LONG = i32;
pub type USHORT = u16;
pub type UCHAR = u8;
pub type CHAR = i8;
pub type BOOLEAN = u8;
pub type BOOL = i32;
pub type DWORD = u32;
pub type DWORD_PTR = usize;
pub type PWSTR = *mut u16;
pub type LPWSTR = *mut u16;
pub type NTSTATUS = i32;
pub type PCWSTR = *const u16;
pub type LPCWSTR = *const u16;
pub type HRESULT = i32;

//Punteros
pub type PVOID = *mut c_void;
pub type LPVOID = *mut c_void;
pub type LPCVOID = *const c_void;
pub type PULONG = *mut u32;
pub type LPDWORD = *mut u32;
pub type PHANDLE = *mut HANDLE;
pub type PCUNICODE_STRING = *const UNICODE_STRING;

// WinHTTP
pub type HINTERNET = *mut c_void;
pub type INTERNET_PORT = u16;

// COM / OLE
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct GUID {
    pub Data1: u32,
    pub Data2: u16,
    pub Data3: u16,
    pub Data4: [u8; 8],
}

pub type CLSID = GUID;
pub type IID = GUID;
pub type REFCLSID = *const IID;
pub type REFIID = *const IID;
pub type LPUNKNOWN = *mut c_void;


//ERRORES NT
pub const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820; // 0xC0000004 en i32

//Listas
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

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

impl UNICODE_STRING {
    pub fn is_empty(&self) -> bool {
        self.Length == 0 || self.Buffer.is_null()
    }

    pub fn as_slice(&self) -> &[u16] {
        if self.Buffer.is_null() || self.Length == 0 {
            &[]
        } else {
            unsafe {
                std::slice::from_raw_parts(self.Buffer, (self.Length / 2) as usize)
            }
        }
    }

    pub fn to_string(&self) -> String {
        String::from_utf16_lossy(self.as_slice())
    }

    pub fn as_string(&self) -> String {
        self.to_string()
    }
}

impl std::fmt::Display for UNICODE_STRING {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
#[macro_export]
macro_rules! unicode_string {
    ($s:expr) => {{
        const S: &str = $s;
        const LEN: usize = S.len();
        // Se genera un array estático en tiempo de compilación en .rdata
        static WSTR: [u16; LEN + 1] = {
            let bytes = S.as_bytes();
            let mut buf = [0u16; LEN + 1];
            let mut i = 0;
            while i < LEN {
                buf[i] = bytes[i] as u16;
                i += 1;
            }
            buf[LEN] = 0;
            buf
        };

        $crate::nt::types::UNICODE_STRING {
            Length: (LEN * 2) as u16,
            MaximumLength: ((LEN + 1) * 2) as u16,
            Buffer: WSTR.as_ptr() as *mut u16,
        }
    }};
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
