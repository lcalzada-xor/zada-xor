use crate::nt::types::*;
use crate::techniques::evasion::dinamic_api_resolution::get_winhttp_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

// Documentación oficial:
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpclosehandle

// Cierra un handle de WinHTTP
pub fn win_http_close_handle(
    h_internet: HINTERNET, // in - handle winhttp a cerrar
) -> Result<(), String> { // ret - éxito o mensaje error
    let api_hash = 0xefee278c; // unique_hash("WinHttpCloseHandle")
    let winhttp_base = unsafe { get_winhttp_base().map_err(|e| e.to_string())? };

    let status = user_mode_call_with_spoof(
        winhttp_base,
        api_hash,
        h_internet as usize,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )?;

    if status == 0 {
        Err(String::from("WinHttpCloseHandle falló (retornó FALSE)"))
    } else {
        Ok(())
    }
}
