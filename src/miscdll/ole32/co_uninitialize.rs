use crate::techniques::evasion::dinamic_api_resolution::get_ole32_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

// Documentación oficial:
// https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-couninitialize

/// Cierra la biblioteca COM en el subproceso actual, descarga todas las DLL cargadas
/// por el subproceso, libera los demás recursos que mantiene y fuerza el cierre de todas
/// las conexiones RPC en el subproceso.
pub fn co_uninitialize() -> Result<(), String> {
    let api_hash = 0xb6f7a996; // unique_hash("CoUninitialize")
    let ole32_base = unsafe { get_ole32_base().map_err(|e| e.to_string())? };

    user_mode_call_with_spoof(
        ole32_base,
        api_hash,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )?;

    Ok(())
}
