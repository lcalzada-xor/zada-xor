// Implementación futura de NtDuplicateObject
use crate::nt::types::*;
use crate::techniques::evasion::execution::dinamic_ssn::get_dinamic_ssn;
use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;

//https://ntdoc.m417z.com/ntduplicateobject

// Flags para el parámetro `options`
pub const DUPLICATE_CLOSE_SOURCE: ULONG = 0x00000001;
pub const DUPLICATE_SAME_ACCESS: ULONG = 0x00000002;
pub const DUPLICATE_SAME_ATTRIBUTES: ULONG = 0x00000004;

// Flags para el parámetro `handle_atributes` (OBJ_*)
pub const OBJ_INHERIT: ULONG = 0x00000002;
pub const OBJ_PERMANENT: ULONG = 0x00000010;
pub const OBJ_EXCLUSIVE: ULONG = 0x00000020;
pub const OBJ_CASE_INSENSITIVE: ULONG = 0x00000040;
pub const OBJ_OPENIF: ULONG = 0x00000080;
pub const OBJ_OPENLINK: ULONG = 0x00000100;
pub const OBJ_KERNEL_HANDLE: ULONG = 0x00000200;
pub const OBJ_FORCE_ACCESS_CHECK: ULONG = 0x00000400;
pub const OBJ_DONT_REPARSE: ULONG = 0x00001000;

pub fn nt_duplicate_object( //pude duplicar kernel objects como handles
    source_process_handle: HANDLE, //in
    source_handle: HANDLE, //in
    target_process_handle: HANDLE, //in_opt
    target_handle: PHANDLE, //out_opt
    desired_access: ACCESS_MASK, //in
    handle_atributes: ULONG, //in
    options: ULONG,//in
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
