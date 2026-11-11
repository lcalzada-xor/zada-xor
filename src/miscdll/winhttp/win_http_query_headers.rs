use crate::nt::types::*;
use crate::techniques::evasion::dinamic_api_resolution::get_winhttp_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

// Documentación oficial:
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpqueryheaders

// Flags comunes de información para dwInfoLevel (Query Info Flags)
pub const WINHTTP_QUERY_STATUS_CODE: DWORD = 19;
pub const WINHTTP_QUERY_STATUS_TEXT: DWORD = 20;
pub const WINHTTP_QUERY_RAW_HEADERS: DWORD = 21;
pub const WINHTTP_QUERY_RAW_HEADERS_CRLF: DWORD = 22;
pub const WINHTTP_QUERY_CONTENT_TYPE: DWORD = 1;
pub const WINHTTP_QUERY_CONTENT_LENGTH: DWORD = 5;
pub const WINHTTP_QUERY_CUSTOM: DWORD = 65535;

// Flags modificadores de formato
pub const WINHTTP_QUERY_FLAG_REQUEST_HEADERS: DWORD = 0x80000000;
pub const WINHTTP_QUERY_FLAG_SYSTEMTIME: DWORD = 0x40000000;
pub const WINHTTP_QUERY_FLAG_NUMBER: DWORD = 0x20000000;

// Constantes de conveniencia
pub const WINHTTP_HEADER_NAME_BY_INDEX: LPCWSTR = std::ptr::null();
pub const WINHTTP_NO_OUTPUT_BUFFER: LPVOID = std::ptr::null_mut();
pub const WINHTTP_NO_HEADER_INDEX: LPDWORD = std::ptr::null_mut();

// Consulta y extrae cabeceras HTTP
pub fn win_http_query_headers(
    h_request: HINTERNET,        // in - handle petición con respuesta
    dw_info_level: DWORD,        // in - flag de información solicitada
    pwsz_name: LPCWSTR,          // in_opt - nombre de cabecera personalizada
    lp_buffer: LPVOID,           // out - buffer donde recibe datos
    lpdw_buffer_length: LPDWORD, // in_out - tamaño buffer en bytes
    lpdw_index: LPDWORD,         // in_out - índice para cabeceras repetidas
) -> Result<(), String> { // ret - éxito o mensaje error
    let api_hash = 0x8ea10460; // unique_hash("WinHttpQueryHeaders")
    let winhttp_base = unsafe { get_winhttp_base().map_err(|e| e.to_string())? };

    let status = user_mode_call_with_spoof(
        winhttp_base,
        api_hash,
        h_request as usize,
        dw_info_level as usize,
        pwsz_name as usize,
        lp_buffer as usize,
        lpdw_buffer_length as usize,
        lpdw_index as usize,
        0,
        0,
    )?;

    if status == 0 {
        Err(String::from("WinHttpQueryHeaders falló (retornó FALSE)"))
    } else {
        Ok(())
    }
}
