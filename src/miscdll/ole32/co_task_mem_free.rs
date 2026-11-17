use crate::nt::types::*;
use crate::techniques::evasion::dinamic_api_resolution::get_ole32_base;
use crate::techniques::evasion::execution::user_mode_call::user_mode_call_with_spoof;

// Documentación oficial:
// https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cotaskmemfree

/// Libera un bloque de memoria de tarea previamente asignado mediante CoTaskMemAlloc o CoTaskMemRealloc.
/// Si `pv` es NULL, la función no tiene ningún efecto.
pub fn co_task_mem_free(pv: LPVOID) -> Result<(), String> {
    let api_hash = 0x8e42fd9a; // unique_hash("CoTaskMemFree")
    let ole32_base = unsafe { get_ole32_base().map_err(|e| e.to_string())? };

    user_mode_call_with_spoof(
        ole32_base,
        api_hash,
        pv as usize,
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
