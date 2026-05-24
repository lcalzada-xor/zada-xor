use crate::utils::*;
use super::offsets;
use std::arch::asm;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsVersion {
    Win11,
    Win10,
    Win8,
    Win7,
    Vista,
}

impl fmt::Display for OsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            OsVersion::Win11 => "Windows 11",
            OsVersion::Win10 => "Windows 10",
            OsVersion::Win8 => "Windows 8",
            OsVersion::Win7 => "Windows 7",
            OsVersion::Vista => "Windows Vista",
        };
        write!(f, "{}", s)
    }
}

pub struct PebOffsets {
    pub being_debugged: usize,
    pub ldr: usize,
    pub image_base: usize,
    pub process_parameters: usize,
    pub process_heap: usize,
    pub nt_global_flag: usize,
    pub os_major_version: usize,
    pub os_build_number: usize,
    pub number_of_processors: usize,
}

macro_rules! peb_offsets {
    ($m:path) => {{
        use $m as o;
        PebOffsets {
            being_debugged: o::BEING_DEBUGGED,
            ldr: o::LDR,
            image_base: o::IMAGE_BASE_ADDRESS,
            process_parameters: o::PROCESS_PARAMETERS,
            process_heap: o::PROCESS_HEAP,
            nt_global_flag: o::NT_GLOBAL_FLAG,
            os_major_version: o::OS_MAJOR_VERSION,
            os_build_number: o::OS_BUILD_NUMBER,
            number_of_processors: o::NUMBER_OF_PROCESSORS,
        }
    }};
}

pub struct Peb {
    pub ptr: *const u8,
    pub offsets: PebOffsets,
    pub version: OsVersion,
}

impl Peb {
    pub fn new() -> Result<Self, &'static str> {
        let ptr = Self::get_ptr();
        if ptr.is_null() {
            return Err("PEB pointer is null");
        }

        // Bootstrap: use Win10 offsets (os_build_number is stable since Vista).
        #[cfg(target_arch = "x86_64")]
        let bootstrap = peb_offsets!(offsets::peb_x64::win10);
        #[cfg(target_arch = "x86")]
        let bootstrap = peb_offsets!(offsets::peb_x86::win10);

        let major: u32 = unsafe { read_u32(ptr, bootstrap.os_major_version) };
        let build: u16 = unsafe { read_u16(ptr, bootstrap.os_build_number) };

        let version = detect_version(major, build);
        let offsets = Self::offsets_for(version);

        Ok(Self {
            ptr,
            offsets,
            version,
        })
    }

    pub unsafe fn being_debugged(&self) -> bool {
        unsafe { read_u8(self.ptr, self.offsets.being_debugged) != 0 }
    }

    pub unsafe fn image_base(&self) -> *const u8 {
        unsafe { read_ptr(self.ptr, self.offsets.image_base) }
    }

    pub unsafe fn ldr(&self) -> *const u8 {
        unsafe { read_ptr(self.ptr, self.offsets.ldr) }
    }

    pub unsafe fn process_parameters(&self) -> *const u8 {
        unsafe { read_ptr(self.ptr, self.offsets.process_parameters) }
    }

    pub unsafe fn process_heap(&self) -> *const u8 {
        unsafe { read_ptr(self.ptr, self.offsets.process_heap) }
    }

    pub unsafe fn nt_global_flag(&self) -> u32 {
        unsafe { read_u32(self.ptr, self.offsets.nt_global_flag) }
    }

    pub unsafe fn os_major_version(&self) -> u32 {
        unsafe { read_u32(self.ptr, self.offsets.os_major_version) }
    }

    pub unsafe fn os_build_number(&self) -> u16 {
        unsafe { read_u16(self.ptr, self.offsets.os_build_number) }
    }

    pub unsafe fn number_of_processors(&self) -> u32 {
        unsafe { read_u32(self.ptr, self.offsets.number_of_processors) }
    }

    // --- internals -----------------------------------------------------------

    pub fn get_ptr() -> *const u8 {
        let pebdir: *const u8;

        #[cfg(target_arch = "x86_64")]
        unsafe {
            asm!(
                "mov {0}, gs:[0x60]",
                out(reg) pebdir,
                options(nomem, nostack),
            );
        }

        #[cfg(target_arch = "x86")]
        unsafe {
            asm!(
                "mov {0}, fs:[0x30]",
                out(reg) pebdir,
                options(nomem, nostack),
            );
        }

        pebdir
    }

    #[cfg(target_arch = "x86_64")]
    fn offsets_for(version: OsVersion) -> PebOffsets {
        use offsets::peb_x64;
        match version {
            OsVersion::Win11 => peb_offsets!(peb_x64::win11),
            OsVersion::Win10 => peb_offsets!(peb_x64::win10),
            OsVersion::Win8 => peb_offsets!(peb_x64::win8),
            OsVersion::Win7 => peb_offsets!(peb_x64::win7),
            OsVersion::Vista => peb_offsets!(peb_x64::vista),
        }
    }

    #[cfg(target_arch = "x86")]
    fn offsets_for(version: OsVersion) -> PebOffsets {
        use offsets::peb_x86;
        match version {
            OsVersion::Win11 | OsVersion::Win10 => peb_offsets!(peb_x86::win10),
            OsVersion::Win8 => peb_offsets!(peb_x86::win8),
            OsVersion::Win7 => peb_offsets!(peb_x86::win7),
            OsVersion::Vista => peb_offsets!(peb_x86::vista),
        }
    }
}

impl fmt::Debug for Peb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peb")
            .field("ptr", &format_args!("{:#x}", self.ptr as usize))
            .field("version", &self.version)
            .finish()
    }
}

fn detect_version(major: u32, build: u16) -> OsVersion {
    match (major, build) {
        (10, b) if b >= 22000 => OsVersion::Win11,
        (10, _) => OsVersion::Win10,
        (6, b) if b >= 9200 => OsVersion::Win8,
        (6, b) if b >= 7600 => OsVersion::Win7,
        _ => OsVersion::Vista,
    }
}
