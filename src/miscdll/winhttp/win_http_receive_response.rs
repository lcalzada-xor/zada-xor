use crate::nt::types::*;
use crate::techniques::evasion::dinamic_api_resolution::get_winhttp_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

// Documentación oficial:
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpreceiveresponse

// Espera y recibe la respuesta HTTP
pub fn win_http_receive_response(
    h_request: HINTERNET, // in - handle petición enviada previamente
    lp_reserved: LPVOID,  // in - reservado debe ser null
) -> Result<(), String> { // ret - éxito o mensaje error
    let api_hash = 0x21b35fd7; // unique_hash("WinHttpReceiveResponse")
    let winhttp_base = unsafe { get_winhttp_base().map_err(|e| e.to_string())? };

    let status = user_mode_call_with_spoof(
        winhttp_base,
        api_hash,
        h_request as usize,
        lp_reserved as usize,
        0,
        0,
        0,
        0,
        0,
        0,
    )?;

    if status == 0 {
        Err(String::from("WinHttpReceiveResponse falló (retornó FALSE)"))
    } else {
        Ok(())
    }
}
