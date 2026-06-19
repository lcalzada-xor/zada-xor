/* TODO: implementar */
use super::read_process_mem::*;
use super::utils::*;
use crate::techniques::evasion::stack_spoofing::unwind_info::*;
use rand_core::{OsRng, RngCore};

pub fn mem_remote_pattern_find(
    //esto esta pensado para leer patrones de un proceso remoto, o del mismo proceso de la forma mas segura posible evitando punteros
    process_handle: HANDLE,
    pattern: &[u8],
    initial_addr: usize,
    final_addr: usize,
) -> Option<usize> {
    if pattern.is_empty() || final_addr <= initial_addr {
        return None;
    }

    let bytes_to_read = final_addr - initial_addr;

    let buffer = match nt_read_virtual_memory(process_handle, initial_addr, bytes_to_read) {
        Ok(data) => data,
        Err(_) => return None,
    };

    if let Some(pos) = buffer
        .windows(pattern.len())
        .position(|window| window == pattern)
    {
        return Some(initial_addr + pos);
    }

    None
}
pub unsafe fn mem_local_pattern_find(
    // busca entre dos direcciones cualquier patron (puede estar desalineado) (puede ser inseguro)
    patterns: &[&[u8]],
    initial_addr: usize,
    final_addr: usize,
) -> Option<(usize, usize)> {
    if patterns.is_empty() || final_addr <= initial_addr {
        return None;
    }

    let bytes_to_read = final_addr - initial_addr;
    let walking_ptr = initial_addr as *const u8;

    for i in 0..bytes_to_read {
        for (idx, pattern) in patterns.iter().enumerate() {
            if pattern.is_empty() || pattern.len() > (bytes_to_read - i) {
                continue;
            }

            let mut found = true;
            for j in 0..pattern.len() {
                if unsafe { *walking_ptr.add(i + j) != pattern[j] } {
                    found = false;
                    break;
                }
            }

            // (Dirección de memoria donde empieza, Índice del patrón en la lista)
            if found {
                return Some((initial_addr + i, idx));
            }
        }
    }

    None
}

pub struct DataDllFunc {
    pub initial_addr: usize,
    pub final_addr: usize,
}

pub fn get_pdata_func_info(func_rva: u32, dll_base: *const u8) -> Result<DataDllFunc, String> {
    let pdata_entry = match get_pdata_of_func_by_rva(func_rva, dll_base) {
        Ok(entry) => entry,
        Err(e) => return Err(e.to_string()),
    };

    Ok(DataDllFunc {
        initial_addr: dll_base as usize + pdata_entry.begin_address as usize,
        final_addr: dll_base as usize + pdata_entry.end_address as usize,
    })
}

pub fn pdata_pattern_find_starting_at_rand_func(
    dll_base: *const u8,
    patterns: &[&[u8]],
) -> Option<(usize, usize)> {
    let mut rng = OsRng;

    let pdata_array = match get_pdata_array(dll_base) {
        Some(array) => array,
        None => return None,
    };
    let num_entries = pdata_array.len();

    if num_entries == 0 {
        return None;
    }

    let start_idx = (rng.next_u64() as usize) % num_entries; //eleegimos funcion aleatoria
    #[cfg(debug_assertions)]
    println!("[Debug] start_idx: {:#x}", start_idx);
    // se itera por todas las funcs de forma circular
    for i in 0..num_entries {
        // Hacemos wrap-around (módulo) para que si empieza al final, vuelva al principio
        let current_idx = (start_idx + i) % num_entries;
        let entry = pdata_array[current_idx];

        // Obtenemos las VAs reales de la función actual
        let initial_addr = dll_base as usize + entry.begin_address as usize;
        let final_addr = dll_base as usize + entry.end_address as usize;

        // Si la función es inválida o está vacía, saltamos a la siguiente
        if initial_addr >= final_addr {
            continue;
        }

        // Buscamos nuestros patrones solo dentro de los límites de esta función
        if let Some(result) = unsafe { mem_local_pattern_find(patterns, initial_addr, final_addr) }
        {
            return Some(result);
        }
    }

    // Si ha escaneado el 100% de las funciones y no hay nada, devuelve None
    None
}

pub fn find_pattern_in_specific_func(
    patterns: &[&[u8]],
    func_rva: u32,
    dll_base: *const u8,
) -> Option<usize> {
    let func_info = match get_pdata_func_info(func_rva, dll_base) {
        Ok(info) => info,
        Err(_) => return None,
    };
    unsafe { mem_local_pattern_find(patterns, func_info.initial_addr, func_info.final_addr) }
        .map(|(addr, _)| addr)
}
