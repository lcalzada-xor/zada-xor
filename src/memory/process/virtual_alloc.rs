use super::utils::{HANDLE, SIZE_T};
use crate::techniques::evasion::execution::dinamic_ssn::get_dinamic_ssn;
use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;

#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum AllocationType {
    /// Asigna espacio físico (memoria o paginación) para las páginas reservadas y las inicializa en cero.
    MEM_COMMIT = 0x00001000,
    /// Reserva un rango de direcciones virtuales sin asignar almacenamiento físico real.
    MEM_RESERVE = 0x00002000,
    /// Indica que los datos del rango de memoria ya no son de interés y no deben paginarse.
    MEM_RESET = 0x00080000,
    /// Revierte los efectos de un MEM_RESET previo si los datos siguen intactos en memoria.
    MEM_RESET_UNDO = 0x01000000,
    /// Asigna memoria utilizando soporte para páginas grandes (large pages).
    MEM_LARGE_PAGES = 0x20000000,
    /// Reserva un rango de direcciones para mapear extensiones de ventana de direcciones (AWE).
    MEM_PHYSICAL = 0x00400000,
    /// Asigna memoria en la dirección de memoria virtual más alta posible.
    MEM_TOP_DOWN = 0x00100000,
    /// Hace que el sistema realice un seguimiento de las páginas escritas en la región (requiere MEM_RESERVE).
    MEM_WRITE_WATCH = 0x00200000,
}

#[repr(u32)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageProtection {
    /// No se permite ningún acceso a la región confirmada de páginas. Un intento de leer, escribir o ejecutar la región confirmada produce una excepción de infracción de acceso, denominada error de protección general (GP).
    PAGE_NOACCESS = 0x01,
    /// Se permite el acceso de solo lectura y ejecución a la región confirmada de páginas. Un intento de escribir la región confirmada produce una infracción de acceso.
    PAGE_READONLY = 0x02,
    /// Se permite el acceso de lectura, escritura y ejecución a la región confirmada de páginas. Si se permite el acceso de escritura a la sección subyacente, se comparte una sola copia de las páginas. De lo contrario, las páginas se comparten de solo lectura o copia en escritura.
    PAGE_READWRITE = 0x04,
    /// Se permite ejecutar el acceso a la región confirmada de páginas. Un intento de leer o escribir en la región confirmada produce una infracción de acceso.
    PAGE_EXECUTE = 0x10,
    /// Se permite el acceso de ejecución y lectura a la región confirmada de páginas. Un intento de escribir en la región confirmada produce una infracción de acceso.
    PAGE_EXECUTE_READ = 0x20,
    /// Se permite el acceso de ejecución, lectura y escritura a la región confirmada de páginas.
    PAGE_EXECUTE_READWRITE = 0x40,
    /// Las páginas de la región se convierten en páginas de protección. Cualquier intento de leer o escribir en una página de protección hace que el sistema genere una excepción de STATUS_GUARD_PAGE. Por lo tanto, las páginas de protección actúan como una alarma de acceso único. Esta marca es un modificador de protección de página, válido solo cuando se usa con una de las marcas de protección de página que no sean PAGE_NOACCESS. Cuando un intento de acceso lleva al sistema a desactivar el estado de la página de protección, la protección de páginas subyacente toma el control. Si se produce una excepción de página de protección durante un servicio del sistema, el servicio normalmente devuelve un indicador de estado de error.
    PAGE_GUARD = 0x100,
    /// La región de las páginas debe asignarse como noquecheable. PAGE_NOCACHE no se permite para las secciones.
    PAGE_NOCACHE = 0x200,
    /// Habilita la combinación de escritura, es decir, la fusión de escrituras de la memoria caché a la memoria principal, donde el hardware lo admite. Esta marca se usa principalmente para la memoria del búfer de fotogramas para que las escrituras en la misma línea de caché se combinen siempre que sea posible antes de escribirse en el dispositivo. Esto puede reducir considerablemente las escrituras en el bus a la memoria de vídeo (por ejemplo). Si el hardware no admite la combinación de escritura, se omite la marca. Esta marca es un modificador de protección de página, válido solo cuando se usa con una de las marcas de protección de página que no sean PAGE_NOACCESS.
    PAGE_WRITECOMBINE = 0x400,
}

pub fn nt_allocate_virtual_memory(
    process_handle: HANDLE,          // handle del proceso objetivo
    base_addr: *mut u8,              // direccion donde se allocara la memoria
    region_size: SIZE_T,             // tamaño de la memoria a allocar
    allocation_type: AllocationType, // tipo de allocacion
    protect: PageProtection,         // proteccion de la memoria
) -> Result<usize, String> {
    let ssn = get_dinamic_ssn(0x2759addf)?;

    unsafe {
        let mut base_ptr = base_addr;
        let mut size_val = region_size;

        let status = indirect_syscall_6(
            0x2759addf,
            ssn,
            process_handle as usize,
            &mut base_ptr as *mut *mut u8 as usize,
            0,
            &mut size_val as *mut SIZE_T as usize,
            (allocation_type as u32) as usize,
            protect as usize,
        );

        match status {
            Ok(0) => Ok(base_ptr as usize),
            Ok(code) => Err(format!(
                "NtAllocateVirtualMemory devolvió NTSTATUS: {:#X}",
                code
            )),
            Err(e) => Err(e),
        }
    }
}
