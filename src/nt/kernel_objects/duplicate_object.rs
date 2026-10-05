// Implementación futura de NtDuplicateObject
use crate::nt::types::*;
use crate::techniques::evasion::execution::dinamic_ssn::get_dinamic_ssn;
use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;


pub fn nt_duplicate_object(
    source_process_handle: HANDLE,
    source_handle: HANDLE,
    target_process_handle: HANDLE,
    target_handle: PHANDLE,
    desired_access: ACCESS_MASK,
    handle_atributes: ULONG,
    options: ULONG,
) -> Result<usize, String> {
    let api_hash = 0x8f9a8420;
    let ssn = get_dinamic_ssn(api_hash)?;

    unsafe {
        let status = indirect_syscall_6(
            api_hash,
            ssn,
            source_process_handle as usize,
            source_handle as usize,
            target_process_handle as usize,
            target_handle as usize,
            desired_access as usize,
            handle_atributes as usize,
            options as usize,
            0,
        );

        match status {
            Ok(0) => Ok(0),
            Ok(code) => Err(format!("NtDuplicateObject devolvió NTSTATUS: {:#X}", code)),
            Err(e) => Err(e),
        }
    }
}
