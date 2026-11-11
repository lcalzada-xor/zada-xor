use crate::nt::types::*;
use crate::techniques::evasion::dinamic_api_resolution::get_winhttp_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

// Documentación oficial:
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpsendrequest

// Constantes estándar para WinHttpSendRequest
pub const WINHTTP_NO_ADDITIONAL_HEADERS: LPCWSTR = std::ptr::null();
pub const WINHTTP_NO_REQUEST_DATA: LPVOID = std::ptr::null_mut();
pub const WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH: DWORD = 0;

// Envía la petición HTTP al servidor
pub fn win_http_send_request(
    h_request: HINTERNET,      // in - handle petición http
    lpsz_headers: LPCWSTR,     // in_opt - cabeceras http adicionales
    dw_headers_length: DWORD,  // in - longitud cabeceras en caracteres
    lp_optional: LPVOID,       // in_opt - cuerpo opcional post put
    dw_optional_length: DWORD, // in - tamaño cuerpo opcional bytes
    dw_total_length: DWORD,    // in - tamaño total enviado bytes
    dw_context: DWORD_PTR,     // in - valor contexto para callbacks
) -> Result<(), String> { // ret - éxito o mensaje error
    let api_hash = 0x9985ccdf; // unique_hash("WinHttpSendRequest")
    let winhttp_base = unsafe { get_winhttp_base().map_err(|e| e.to_string())? };

    let status = user_mode_call_with_spoof(
        winhttp_base,
        api_hash,
        h_request as usize,
        lpsz_headers as usize,
        dw_headers_length as usize,
        lp_optional as usize,
        dw_optional_length as usize,
        dw_total_length as usize,
        dw_context as usize,
        0,
    )?;

    if status == 0 {
        Err(String::from("WinHttpSendRequest falló (retornó FALSE)"))
    } else {
        Ok(())
    }
}
