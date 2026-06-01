#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use crate::techniques::evasion::execution::dinamic_ssn::get_dinamic_ssn;
use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;
use std::ffi::c_void;

pub type HANDLE = *mut c_void;

pub type SIZE_T = usize;

/*
QueryVirtualMemory seria como la generacion de un mapa de memoria de un proceso,
es decir, nos diria donde empieza cada region de memoria, que tamaño tiene y que permisos tiene.
*/

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0,
    MemoryWorkingSetInformation = 1,
    MemoryMappedFilenameInformation = 2,
    MemoryRegionInformation = 3,
    MemoryWorkingSetExInformation = 4,
    MemorySharedCommitInformation = 5,
    MemoryImageInformation = 6,
    MemoryRegionInformationEx = 7,
    MemoryPrivilegedBasicInformation = 8,
    MemoryEnclaveImageInformation = 9,
    MemoryBasicInformationCapped = 10,
    MemoryPhysicalContiguityInformation = 11,
    MemoryBadInformation = 12,
    MemoryBadInformationAllProcesses = 13,
    MemoryImageExtensionInformation = 14,
    MaxMemoryInfoClass = 15,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: *mut c_void,
    pub AllocationBase: *mut c_void,
    pub AllocationProtect: u32,
    #[cfg(target_pointer_width = "64")]
    pub PartitionId: u16,
    pub RegionSize: SIZE_T,
    pub State: u32,
    pub Protect: u32,
    pub Type: u32,
}

impl Default for MEMORY_BASIC_INFORMATION {
    fn default() -> Self {
        MEMORY_BASIC_INFORMATION {
            BaseAddress: core::ptr::null_mut(),
            AllocationBase: core::ptr::null_mut(),
            AllocationProtect: 0,
            PartitionId: 0,
            RegionSize: 0,
            State: 0,
            Protect: 0,
            Type: 0,
        }
    }
}

impl MEMORY_BASIC_INFORMATION {
    pub fn new() -> Self {
        Self::default()
    }
}

pub fn nt_query_virtual_memory(
    process_handle: HANDLE,
    base_address: usize,
) -> Result<MEMORY_BASIC_INFORMATION, String> {
    let ssn = get_dinamic_ssn(0xbe409009)?;
    let mut mem_basic_info = MEMORY_BASIC_INFORMATION::new();
    unsafe {
        let status = indirect_syscall_6(
            0xbe409009,
            ssn,
            process_handle as usize,
            base_address,
            MEMORY_INFORMATION_CLASS::MemoryBasicInformation as usize,
            &mut mem_basic_info as *mut MEMORY_BASIC_INFORMATION as usize,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            0,
        );

        match status {
            Ok(return_value) => match return_value {
                0 => Ok(mem_basic_info),
                _ => Err(String::from(format!(
                    "Error en la llamada a NtQueryVirtualMemory: {:#X}",
                    return_value
                ))),
            },
            Err(e) => Err(e),
        }
    }
}

pub fn escanear_memoria_proceso(process_handle: HANDLE) {
    let mut current_address: usize = 0x00000;

    let mut regiones_encontradas = 0;

    println!("┌──────────────────────────────────────┬──────────────────────────┬────────────┐");
    println!("│ Dirección Base                       │ Tamaño de la Región      │ Tipo       │");
    println!("├──────────────────────────────────────┼──────────────────────────┼────────────┤");

    loop {
        match nt_query_virtual_memory(process_handle, current_address) {
            Ok(mbi) => {
                if mbi.RegionSize == 0 {
                    current_address += 0x1000;
                    continue;
                }

                const MEM_COMMIT: u32 = 0x1000;
                const PAGE_READWRITE: u32 = 0x04;
                const PAGE_EXECUTE_READWRITE: u32 = 0x40;

                if mbi.State == MEM_COMMIT {
                    if mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE {
                        let tipo = if mbi.Protect == PAGE_EXECUTE_READWRITE {
                            "RWX"
                        } else {
                            "RW"
                        };
                        let formatted_base = format!("{:p}", mbi.BaseAddress);
                        let formatted_size = format!("{:#X} bytes", mbi.RegionSize);
                        println!(
                            "│ {:<36} │ {:>26} │ {:^10} │",
                            formatted_base, formatted_size, tipo
                        );
                        regiones_encontradas += 1;
                    }
                }

                current_address = mbi.BaseAddress as usize + mbi.RegionSize;
            }
            Err(e) => {
                println!(
                    "└──────────────────────────────────────┴──────────────────────────┴────────────┘"
                );
                println!("[!] El bucle se detuvo. Motivo: {}", e);
                break;
            }
        }

        if current_address >= 0x7FFFFFFFFFFF {
            println!(
                "└──────────────────────────────────────┴──────────────────────────┴────────────┘"
            );
            println!("[*] Se alcanzó el fin del espacio de direcciones de usuario.");
            break;
        }
    }

    println!(
        "[*] Escaneo finalizado. Total de regiones válidas mapeadas: {}",
        regiones_encontradas
    );
}
