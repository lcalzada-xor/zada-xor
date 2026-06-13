use crate::structures::pe::export::ExportTable;
#[cfg(target_arch = "x86_64")]
use crate::structures::peb::ldr::offsets::x64::IN_LOAD_ORDER_MODULE_LIST;
#[cfg(target_arch = "x86")]
use crate::structures::peb::ldr::offsets::x86::IN_LOAD_ORDER_MODULE_LIST;
use crate::structures::peb::ldr_entry::LdrDataTableEntry;
#[cfg(target_arch = "x86_64")]
use crate::structures::peb::ldr_entry::offsets::x64_win10 as ldr_off;
#[cfg(target_arch = "x86")]
use crate::structures::peb::ldr_entry::offsets::x86_win10 as ldr_off;
use crate::structures::peb::list_entry::ListEntry;
use crate::structures::peb::peb::Peb;
use crate::techniques::evasion::api_hashing::unique_hash;

pub unsafe fn get_ntdll_base() -> Result<*const u8, &'static str> {
    unsafe {
        let peb = Peb::new().unwrap();
        let ldr_ptr = peb.ldr();

        let head = ListEntry::new(ldr_ptr.add(IN_LOAD_ORDER_MODULE_LIST));

        for (_i, node) in head.iter().enumerate() {
            let entry_ptr = ListEntry::new(node).containing_record(ldr_off::IN_LOAD_ORDER_LINKS);
            let entry = LdrDataTableEntry::new(entry_ptr);

            if unique_hash(
                &entry
                    .base_dll_name()
                    .expect("Full DLL name not found")
                    .to_lowercase(),
            ) == 0x68861c6f
            {
                return Ok(entry.dll_base());
            }
        }

        Err("Ntdll.dll Module not found")
    }
}

pub unsafe fn get_kernel32_base() -> Result<*const u8, &'static str> {
    unsafe {
        let peb = Peb::new().unwrap();
        let ldr_ptr = peb.ldr();

        let head = ListEntry::new(ldr_ptr.add(IN_LOAD_ORDER_MODULE_LIST));

        for (_i, node) in head.iter().enumerate() {
            let entry_ptr = ListEntry::new(node).containing_record(ldr_off::IN_LOAD_ORDER_LINKS);
            let entry = LdrDataTableEntry::new(entry_ptr);

            if unique_hash(
                &entry
                    .base_dll_name()
                    .expect("Full DLL name not found")
                    .to_lowercase(),
            ) == 0xd32210ae
            {
                return Ok(entry.dll_base());
            }
        }

        Err("Kernel32.dll Module not found")
    }
}
pub unsafe fn get_dll_base_by_hash(hash: u32) -> Result<*const u8, &'static str> {
    unsafe {
        let peb = Peb::new().unwrap();
        let ldr_ptr = peb.ldr();

        let head = ListEntry::new(ldr_ptr.add(IN_LOAD_ORDER_MODULE_LIST));

        for (_i, node) in head.iter().enumerate() {
            let entry_ptr = ListEntry::new(node).containing_record(ldr_off::IN_LOAD_ORDER_LINKS);
            let entry = LdrDataTableEntry::new(entry_ptr);

            if unique_hash(
                &entry
                    .base_dll_name()
                    .expect("Full DLL name not found")
                    .to_lowercase(),
            ) == hash
            {
                return Ok(entry.dll_base());
            }
        }

        Err("Module not found")
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
