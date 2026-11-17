use crate::nt::types::*;
use crate::techniques::evasion::dinamic_api_resolution::get_ole32_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

// Documentación oficial:
// https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance

// Constantes de contexto de clase (CLSCTX)
pub const CLSCTX_INPROC_SERVER: DWORD = 0x1;
pub const CLSCTX_INPROC_HANDLER: DWORD = 0x2;
pub const CLSCTX_LOCAL_SERVER: DWORD = 0x4;
pub const CLSCTX_INPROC_SERVER16: DWORD = 0x8;
pub const CLSCTX_REMOTE_SERVER: DWORD = 0x10;
pub const CLSCTX_ALL: DWORD = CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER;
pub const CLSCTX_SERVER: DWORD = CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER;

// Códigos HRESULT comunes retornados por CoCreateInstance
pub const S_OK: HRESULT = 0x00000000;
pub const REGDB_E_CLASSNOTREG: HRESULT = 0x80040154u32 as i32;
pub const CLASS_E_NOAGGREGATION: HRESULT = 0x80040110u32 as i32;
pub const E_NOINTERFACE: HRESULT = 0x80004002u32 as i32;
pub const E_POINTER: HRESULT = 0x80004003u32 as i32;

/// Crea un único objeto no inicializado de la clase asociada con un CLSID especificado.
///
/// # Parámetros
/// - `rclsid`: El CLSID asociado con los datos y el código que se usarán para crear el objeto.
/// - `p_unk_outer`: Si es NULL, indica que el objeto no se está creando como parte de un agregado.
/// - `dw_cls_context`: Contexto en el que se ejecutará el código que administra el objeto recién creado (p. ej., `CLSCTX_INPROC_SERVER`).
/// - `riid`: Referencia al identificador de la interfaz (IID) que se usará para comunicarse con el objeto.
/// - `ppv`: Dirección de la variable de puntero que recibe el puntero de interfaz solicitado en `riid`.
///
/// # Retorno
/// Retorna `Ok(HRESULT)` con el código HRESULT resultante (típicamente `S_OK`), o `Err(String)` si falla el spoofing o la resolución de la API.
pub fn co_create_instance(
    rclsid: REFCLSID,
    p_unk_outer: LPUNKNOWN,
    dw_cls_context: DWORD,
    riid: REFIID,
    ppv: *mut LPVOID,
) -> Result<HRESULT, String> {
    let api_hash = 0x69c6aed5; // unique_hash("CoCreateInstance")
    let ole32_base = unsafe { get_ole32_base().map_err(|e| e.to_string())? };

    let status = user_mode_call_with_spoof(
        ole32_base,
        api_hash,
        rclsid as usize,
        p_unk_outer as usize,
        dw_cls_context as usize,
        riid as usize,
        ppv as usize,
        0,
        0,
        0,
    )?;

    Ok(status as i32)
}
