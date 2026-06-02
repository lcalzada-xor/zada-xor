use super::utils::HANDLE;
use crate::techniques::evasion::execution::dinamic_ssn::get_dinamic_ssn;
use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;

pub fn nt_close(handle: HANDLE) -> Result<(), String> {
    let hash_nt_close = 0x1c0fcdc4;
    let ssn = get_dinamic_ssn(hash_nt_close)?;

    unsafe {
        let status = indirect_syscall_6(hash_nt_close, ssn, handle as usize, 0, 0, 0, 0, 0);

        match status {
            Ok(0) => Ok(()),
            Ok(code) => Err(format!("NtClose falló con NTSTATUS: {:#X}", code)),
            Err(e) => Err(e),
        }
    }
}
