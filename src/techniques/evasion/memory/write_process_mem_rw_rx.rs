use crate::nt::types::HANDLE;
use crate::nt::memory::write_process_mem::nt_write_virtual_memory;
use crate::nt::memory::protect_virtual_mem::{MemoryProtection, nt_protect_virtual_memory};
use crate::nt::memory::virtual_alloc::{AllocationType, PageProtection, nt_allocate_virtual_memory};


pub fn write_process_mem_rw_rx(handle: HANDLE, bytes_to_write: &[u8]) -> Result<usize, String> {

    let allocated_addr = nt_allocate_virtual_memory(
        handle,
        0 as *mut u8,
        bytes_to_write.len(),
        AllocationType::MEM_COMMIT,
        PageProtection::PAGE_READWRITE,
    )
    .map_err(|e| format!("Fallo al asignar memoria virtual: {}", e))?;

    #[cfg(debug_assertions)]
    println!("[+] Memoria allocada: {:#x}", allocated_addr);

    let bytes_escritos = nt_write_virtual_memory(handle, allocated_addr, bytes_to_write)
        .map_err(|e| format!("Fallo al escribir en la memoria del proceso: {}", e))?;

    if bytes_escritos != bytes_to_write.len() {
        return Err(format!(
            "Incoincidencia: los bytes escritos ({}) no corresponden a los esperados ({})",
            bytes_escritos,
            bytes_to_write.len()
        ));
    }

    #[cfg(debug_assertions)]
    println!("[+] Bytes escritos: {}", bytes_escritos);

    nt_protect_virtual_memory(
        handle,
        allocated_addr,
        bytes_to_write.len(),
        MemoryProtection::ExecuteRead,
    )
    .map_err(|e| format!("Fallo al cambiar la protección de memoria a RX: {}", e))?;

    #[cfg(debug_assertions)]
    println!("[+] Memoria protegida a RX: {:#x}", allocated_addr);


    Ok(allocated_addr)
}
