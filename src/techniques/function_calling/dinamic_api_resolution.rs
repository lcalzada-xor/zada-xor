#[cfg(target_arch = "x86_64")]
use crate::structures::ldr::offsets::x64::IN_LOAD_ORDER_MODULE_LIST;
#[cfg(target_arch = "x86")]
use crate::structures::ldr::offsets::x86::IN_LOAD_ORDER_MODULE_LIST;
use crate::structures::ldr_entry::LdrDataTableEntry;
#[cfg(target_arch = "x86_64")]
use crate::structures::ldr_entry::offsets::x64_win10 as ldr_off;
#[cfg(target_arch = "x86")]
use crate::structures::ldr_entry::offsets::x86_win10 as ldr_off;
use crate::structures::list_entry::ListEntry;
use crate::structures::pe::ExportTable;
use crate::structures::peb::Peb;
use crate::techniques::function_calling::api_hashing::unique_hash;

pub unsafe fn get_ntdll_base() -> *const u8 {
    unsafe {
        let peb = Peb::new().unwrap();
        let ldr_ptr = peb.ldr();

        let head = ListEntry::new(ldr_ptr.add(IN_LOAD_ORDER_MODULE_LIST));

        for (i, node) in head.iter().enumerate() {
            let entry_ptr = ListEntry::new(node).containing_record(ldr_off::IN_LOAD_ORDER_LINKS);
            let entry = LdrDataTableEntry::new(entry_ptr);

            if i == 1 {
                return entry.dll_base();
            }
        }

        core::ptr::null()
    }
}
pub unsafe fn get_export_by_name(
    module: *const u8,
    func_name: &str,
) -> Result<*const u8, &'static str> {
    let export_table = unsafe { ExportTable::new(module) }.ok_or("Invalid Export Table")?;

    for entry in export_table.entries {
        if let Some(ref name) = entry.name {
            if name == func_name {
                let func_ptr = unsafe { module.add(entry.rva as usize) };
                return Ok(func_ptr);
            }
        }
    }

    Err("Function not found")
}

pub fn get_export_by_name_hash(module: *const u8, hash: u32) -> Result<*const u8, &'static str> {
    let export_table = unsafe { ExportTable::new(module) }.ok_or("Invalid Export Table")?;
    for entry in export_table.into_entries() {
        if let Some(ref name) = entry.name {
            if unique_hash(name) == hash {
                let func_ptr = unsafe { module.add(entry.rva as usize) };
                return Ok(func_ptr);
            }
        }
    }

    Err("Function not found")
}

// x86: cdecl — el caller limpia el stack (CRT: strcpy, memcpy, sprintf...)
// x86: stdcall — el callee limpia el stack (WinAPI: VirtualAlloc, NtAllocateVirtualMemory...)
// x64: solo existe una ABI (Microsoft x64), así que cdecl y stdcall son lo mismo.

type CdeclCall = unsafe extern "C" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> isize;

type StdcallCall = unsafe extern "system" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> isize;

fn unpack(
    args: &[usize],
) -> (
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) {
    (
        *args.get(0).unwrap_or(&0),
        *args.get(1).unwrap_or(&0),
        *args.get(2).unwrap_or(&0),
        *args.get(3).unwrap_or(&0),
        *args.get(4).unwrap_or(&0),
        *args.get(5).unwrap_or(&0),
        *args.get(6).unwrap_or(&0),
        *args.get(7).unwrap_or(&0),
        *args.get(8).unwrap_or(&0),
        *args.get(9).unwrap_or(&0),
    )
}

/// Llama funciones cdecl: CRT (strcpy, memcpy, sprintf...).
/// En x64 es equivalente a call_stdcall.
pub unsafe fn call_cdecl(func_ptr: *const u8, args: &[usize]) -> isize {
    let f: CdeclCall = unsafe { std::mem::transmute(func_ptr) };
    let (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) = unpack(args);
    unsafe { f(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) }
}

/// Llama funciones stdcall: WinAPI (VirtualAlloc, NtAllocateVirtualMemory...).
/// En x64 es equivalente a call_cdecl.
pub unsafe fn call_stdcall(func_ptr: *const u8, args: &[usize]) -> isize {
    let f: StdcallCall = unsafe { std::mem::transmute(func_ptr) };
    let (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) = unpack(args);
    unsafe { f(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) }
}
