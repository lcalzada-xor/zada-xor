use crate::nt::types::*;
use crate::techniques::evasion::dinamic_api_resolution::get_ole32_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

//https://learn.microsoft.com/es-es/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex

// Códigos de éxito (bit 31 = 0 -> positivos)
pub const S_OK: HRESULT = 0x00000000;
pub const S_FALSE: HRESULT = 0x00000001;

// Códigos de error (bit 31 = 1 -> cast desde u32 a i32)
pub const E_UNEXPECTED: HRESULT = 0x8000FFFFu32 as i32;
pub const E_INVALIDARG: HRESULT = 0x80070057u32 as i32;
pub const E_OUTOFMEMORY: HRESULT = 0x8007000Eu32 as i32;
pub const RPC_E_CHANGED_MODE: HRESULT = 0x80010106u32 as i32;

#[derive(Debug, PartialEq, Eq)]
pub enum ComInitStatus {
    /// S_OK: Inicializado por primera vez en este hilo (requiere CoUninitialize)
    Initialized,
    /// S_FALSE: Ya estaba inicializado en este hilo con el mismo modo (requiere CoUninitialize)
    AlreadyInitialized,
    /// RPC_E_CHANGED_MODE: Ya estaba activo con otro modo, ej. STA (NO llamar a CoUninitialize)
    ChangedMode,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ComInitError {
    InvalidArg,
    OutOfMemory,
    Unexpected,
    Other(HRESULT),
}

pub fn co_initialize_ex(pv_reserved: LPVOID, dw_co_init: DWORD) -> Result<ComInitStatus, ComInitError> {
    // unique_hash("CoInitializeEx") = 0x2530a98
    let api_hash = 0x2530a98; 
    let ole32_base = unsafe { 
        get_ole32_base().map_err(|_| ComInitError::Unexpected)? 
    };

    let result = user_mode_call_with_spoof(
        ole32_base,
        api_hash,
        pv_reserved as usize,
        dw_co_init as usize,
        0,
        0,
        0,
        0,
        0,
        0,
    ).map_err(|_| ComInitError::Unexpected)?;

    let hr = result as i32;

    match hr {
        S_OK => Ok(ComInitStatus::Initialized),
        S_FALSE => Ok(ComInitStatus::AlreadyInitialized),
        RPC_E_CHANGED_MODE => Ok(ComInitStatus::ChangedMode),
        E_INVALIDARG => Err(ComInitError::InvalidArg),
        E_OUTOFMEMORY => Err(ComInitError::OutOfMemory),
        E_UNEXPECTED => Err(ComInitError::Unexpected),
        other => Err(ComInitError::Other(other)),
    }
}