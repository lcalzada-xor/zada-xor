use crate::nt::types::HANDLE;
use crate::techniques::evasion::execution::dinamic_ssn::get_dinamic_ssn;
use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;

#[repr(u32)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessInformationClass {
    /// Recupera un puntero a una estructura PEB que se puede usar para determinar si se está depurando el proceso especificado y un valor único utilizado por el sistema para identificar el proceso especificado.
    /// Use las funciones CheckRemoteDebuggerPresent y GetProcessId para obtener esta información.
    ProcessBasicInformation = 0,

    /// Recupera un valor de DWORD_PTR que es el número de puerto del depurador para el proceso. Un valor distinto de cero indica que el proceso se está ejecutando bajo el control de un depurador de anillo 3.
    /// Use la función CheckRemoteDebuggerPresent o IsDebuggerPresent.
    ProcessDebugPort = 7,

    /// Determina si el proceso se ejecuta en el entorno WOW64 (WOW64 es el emulador x86 que permite que las aplicaciones basadas en Win32 se ejecuten en Windows de 64 bits).
    /// Use la función IsWow64Process2 para obtener esta información.
    ProcessWow64Information = 26,

    /// Recupera un valor UNICODE_STRING que contiene el nombre del archivo de imagen para el proceso.
    /// Use la función QueryFullProcessImageName o GetProcessImageFileName para obtener esta información.
    ProcessImageFileName = 27,

    /// Recupera un valor de ULONG que indica si el proceso se considera crítico.
    /// Nota Este valor se puede usar a partir de Windows XP con SP3. A partir de Windows 8.1, se debe usar IsProcessCritical en su lugar.
    ProcessBreakOnTermination = 29,

    /// Recupera una estructura PROCESS_HANDLE_SNAPSHOT_INFORMATION que contiene información sobre los handles (identificadores) abiertos por el proceso.
    ProcessHandleInformation = 51,

    /// Recupera un valor de PROCESS_TELEMETRY_ID_INFORMATION_TYPE que contiene metadatos sobre un proceso.
    ProcessTelemetryIdInformation = 64,

    /// Recupera un valor SUBSYSTEM_INFORMATION_TYPE que indica el tipo de subsistema del proceso. El búfer al que apunta el parámetro ProcessInformation debe ser lo suficientemente grande como para contener una sola enumeración SUBSYSTEM_INFORMATION_TYPE.
    ProcessSubsystemInformation = 75,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub struct PROCESS_HANDLE_TABLE_ENTRY_INFO {
    pub HandleValue: HANDLE,
    pub HandleCount: usize,
    pub PointerCount: usize,
    pub GrantedAccess: u32,
    pub ObjectTypeIndex: u32,
    pub HandleAttributes: u32,
    pub Reserved: u32,
}

#[allow(non_camel_case_types)]
pub type PPROCESS_HANDLE_TABLE_ENTRY_INFO = *mut PROCESS_HANDLE_TABLE_ENTRY_INFO;

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug)]
pub struct PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    pub NumberOfHandles: usize,
    pub Reserved: usize,
    pub Handles: [PROCESS_HANDLE_TABLE_ENTRY_INFO; 1],
}

#[allow(non_camel_case_types)]
pub type PPROCESS_HANDLE_SNAPSHOT_INFORMATION = *mut PROCESS_HANDLE_SNAPSHOT_INFORMATION;

pub fn query_information_process(process_handle: HANDLE) -> Result<Vec<u8>, String> {
    let ssn = get_dinamic_ssn(0x6fa0c1f4)?;
    let info_class = ProcessInformationClass::ProcessHandleInformation;

    // Estimación inicial base: tamaño de la cabecera + espacio inicial para handles
    let initial_size = std::mem::size_of::<PROCESS_HANDLE_SNAPSHOT_INFORMATION>() + (std::mem::size_of::<PROCESS_HANDLE_TABLE_ENTRY_INFO>() * 64);
    let mut return_length: u32 = initial_size as u32;

    const MAX_ATTEMPTS: usize = 10;
    const STATUS_SUCCESS: u32 = 0;
    const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC0000004;

    for _ in 0..MAX_ATTEMPTS {
        let mut buffer: Vec<u8> = vec![0u8; return_length as usize];
        let mut required_length: u32 = 0;

        unsafe {
            let status = indirect_syscall_6(
                0x6fa0c1f4,
                ssn,
                process_handle as usize,
                info_class as u32 as usize,
                buffer.as_mut_ptr() as usize,
                buffer.len(),
                &mut required_length as *mut u32 as usize,
                0,
                0,
                0
            )?;

            match status as u32 {
                STATUS_SUCCESS => return Ok(buffer),
                STATUS_INFO_LENGTH_MISMATCH => {
                    // Si el kernel indica un tamaño mayor, lo usamos con un margen de holgura.
                    // Si devolvió 0, duplicamos el tamaño actual del búfer.
                    return_length = if required_length > 0 {
                        required_length + (std::mem::size_of::<PROCESS_HANDLE_TABLE_ENTRY_INFO>() as u32 * 16)
                    } else {
                        (buffer.len() * 2) as u32
                    };
                }
                _ => {
                    return Err(format!(
                        "NtQueryInformationProcess falló con NTSTATUS: {:#X}",
                        status
                    ));
                }
            }
        }
    }

    Err("Se superó el límite de reintentos para obtener el búfer de handles".into())
}

pub fn print_all_handles_info(process_handle: HANDLE, idx_filter: usize) -> Result<(), String> {
    let buffer = query_information_process(process_handle)?;

    unsafe {
        let handle_info_ptr = buffer.as_ptr() as PPROCESS_HANDLE_SNAPSHOT_INFORMATION;
        if handle_info_ptr.is_null() {
            return Err("El puntero obtenido es nulo".into());
        }

        let handle_info = &*handle_info_ptr;
        println!(
            "Número de handles encontrados: {}",
            handle_info.NumberOfHandles
        );

        if handle_info.NumberOfHandles > 0 {
            let entries = std::slice::from_raw_parts(
                handle_info.Handles.as_ptr(),
                handle_info.NumberOfHandles,
            );

            for (idx, entry) in entries.iter().enumerate() {
                if idx_filter > 0 && idx_filter as u32 == entry.ObjectTypeIndex {
                    println!(
                        "  [Handle {}] Value: {:?}, Access: {:#X}, TypeIndex: {}",
                        idx, entry.HandleValue, entry.GrantedAccess, entry.ObjectTypeIndex
                    );
                }else if idx_filter == 0{
                    println!(
                        "  [Handle {}] Value: {:?}, Access: {:#X}, TypeIndex: {}",
                        idx, entry.HandleValue, entry.GrantedAccess, entry.ObjectTypeIndex
                    );
                }

                    
            }
        }
    }

    Ok(())
}
