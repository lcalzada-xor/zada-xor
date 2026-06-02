use super::utils::HANDLE;
use crate::techniques::evasion::execution::dinamic_ssn::get_dinamic_ssn;
use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;

/*protect_virtual_memory cambialos permisos a una region de memoria
 */

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryProtection {
    /// No se permite ningún acceso a la región de memoria. Cualquier intento de
    /// lectura, escritura o ejecución generará una violación de acceso.
    NoAccess = 0x01,

    /// Permite únicamente operaciones de lectura. Es el flag típico para constantes
    /// y datos estáticos del binario (.rdata).
    ReadOnly = 0x02,

    /// Permite operaciones de lectura y escritura. Es el estado por defecto del
    /// Heap (memoria dinámica) y del Stack (pila).
    ReadWrite = 0x04,

    /// Copia al escribir. Permite que múltiples procesos compartan la misma página
    /// en lectura, pero si uno intenta escribir, el sistema operativo crea una copia
    /// privada para ese proceso.
    WriteCopy = 0x08,

    /// Permite únicamente la ejecución de código. No se puede leer ni escribir en ella
    /// (muy poco común en arquitecturas modernas x64).
    Execute = 0x10,

    /// Permite la ejecución de código y operaciones de lectura. Es el flag estándar
    /// para las secciones de código de los ejecutables y DLLs (.text).
    ExecuteRead = 0x20,

    /// Permite la ejecución, lectura y escritura de código (RWX). Es el permiso que
    /// se suele establecer temporalmente para aplicar parches o instrumentación de código.
    ExecuteReadWrite = 0x40,

    /// Permite la ejecución, lectura y copia al escribir.
    ExecuteWriteCopy = 0x80,

    /// Flag modificador (Guard Page). Se combina con otros modificadores mediante operaciones de bits.
    /// Alerta al sistema operativo la primera vez que se accede a la página (usado para el crecimiento del Stack).
    Guard = 0x100,

    /// Flag modificador. Evita que la región de memoria sea almacenada en la memoria caché del procesador.
    NoCache = 0x200,

    /// Flag modificador. Permite configurar la memoria como "Write-combined", optimizando escrituras consecutivas.
    WriteCombine = 0x400,
}

pub fn nt_protect_virtual_memory(
    process_handle: HANDLE,
    base_address: usize,
    size: usize,
    new_protect: MemoryProtection,
) -> Result<(usize, usize, u32), String> {
    let hash_nt_protect_vm = 0x96e11bf8;
    let ssn = get_dinamic_ssn(hash_nt_protect_vm)?;
    let mut boundary_address = base_address;
    let mut boundary_size = size;
    let mut old_protect: u32 = 0; //esto es para recibir el permiso antiguo

    unsafe {
        let status = indirect_syscall_6(
            hash_nt_protect_vm,
            ssn,
            process_handle as usize,
            &mut boundary_address as *mut usize as usize,
            &mut boundary_size as *mut usize as usize,
            new_protect as usize,
            &mut old_protect as *mut u32 as usize,
            0,
        );

        match status {
            Ok(0) => {
                // dirección alineada por el kernel, el tamaño real afectado y el permiso antiguo
                Ok((boundary_address, boundary_size, old_protect))
            }
            Ok(code) => Err(format!(
                "NtProtectVirtualMemory devolvió NTSTATUS: {:#X}",
                code
            )),
            Err(e) => Err(e),
        }
    }
}
