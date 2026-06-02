#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use crate::techniques::evasion::execution::dinamic_ssn::get_dinamic_ssn;
use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;
use super::utils::HANDLE;

/*
nt_read_virtual_memory seria como leer la memoria de un proceso desde el kernel.
*/

pub fn nt_read_virtual_memory(
    process_handle: HANDLE,
    base_address: usize,
    bytes_to_read: usize,
) -> Result<Vec<u8>, String> {
    let ssn = get_dinamic_ssn(0x7a58c6ca)?;
    let mut buffer: Vec<u8> = vec![0u8; bytes_to_read];
    let mut number_of_bytes_read: usize = 0;
    unsafe {
        let status = indirect_syscall_6(
            0x7a58c6ca,
            ssn,
            process_handle as usize,
            base_address,
            buffer.as_mut_ptr() as usize,
            bytes_to_read,
            &mut number_of_bytes_read as *mut usize as usize,
            0,
        );

        match status {
            Ok(return_value) => match return_value {
                0 => Ok(buffer),
                _ => Err(String::from(format!(
                    "Error en la llamada a NtReadVirtualMemory: {:#X}",
                    return_value
                ))),
            },
            Err(e) => Err(e),
        }
    }
}
