use zada_xor::structures::pe::ExportTable;
use zada_xor::structures::peb::ldr::PebLdrData;
use zada_xor::structures::peb::ldr_entry::LdrDataTableEntry;
#[cfg(target_arch = "x86_64")]
use zada_xor::structures::peb::ldr_entry::offsets::x64_win10 as ldr_off;
#[cfg(target_arch = "x86")]
use zada_xor::structures::peb::ldr_entry::offsets::x86_win10 as ldr_off;
use zada_xor::structures::peb::list_entry::ListEntry;
use zada_xor::structures::peb::peb::Peb;
use zada_xor::techniques::evasion::api_hashing::*;
use zada_xor::techniques::evasion::dinamic_api_resolution::*;
use zada_xor::techniques::evasion::execution::direct_syscall::*;
use zada_xor::techniques::evasion::execution::indirect_syscall::*;
use zada_xor::techniques::evasion::execution::normal_call::*;

fn main() {
    let peb = Peb::new().expect("failed to locate PEB");

    println!("{:?}", peb);
    println!("version detectada : {}", peb.version);

    unsafe {
        println!("image_base        : {:#x}", peb.image_base() as usize);
        println!("being_debugged    : {}", peb.being_debugged());
        println!("nt_global_flag    : {:#010x}", peb.nt_global_flag());
        println!("os_build_number   : {}", peb.os_build_number());
        println!("process_heap      : {:#x}", peb.process_heap() as usize);
        println!(
            "process_parameters: {:#x}",
            peb.process_parameters() as usize
        );
        println!("number_of_procs   : {}", peb.number_of_processors());
    }

    unsafe {
        let ldr = PebLdrData::from_ptr(peb.ldr());

        println!("\n--- PEB_LDR_DATA @ {:#x} ---", ldr.ptr as usize);
        println!("initialized            : {}", ldr.initialized());
        println!(
            "in_load_order  (flink) : {:#x}",
            ldr.in_load_order_flink() as usize
        );
        println!(
            "in_memory_order (flink): {:#x}",
            ldr.in_memory_order_flink() as usize
        );
        println!(
            "in_init_order  (flink) : {:#x}",
            ldr.in_init_order_flink() as usize
        );

        #[cfg(target_arch = "x86_64")]
        let head = ListEntry::new(
            ldr.ptr
                .add(zada_xor::structures::peb::ldr::offsets::x64::IN_LOAD_ORDER_MODULE_LIST),
        );
        #[cfg(target_arch = "x86")]
        let head = ListEntry::new(
            ldr.ptr
                .add(zada_xor::structures::peb::ldr::offsets::x86::IN_LOAD_ORDER_MODULE_LIST),
        );

        println!("\n--- InLoadOrderModuleList ({} entries) ---", head.len());
        let mut ntdll: *const u8 = core::ptr::null();
        for (i, node) in head.iter().enumerate() {
            // node points to InLoadOrderLinks inside the entry — recover the parent.
            let entry_ptr = ListEntry::new(node).containing_record(ldr_off::IN_LOAD_ORDER_LINKS);
            let entry = LdrDataTableEntry::new(entry_ptr);

            let name = entry.base_dll_name().unwrap_or_else(|| "<?>".into());
            println!(
                "  [{i:02}] {name:<40} base={:#x}  size={:#x}  ep={:#x}  flags={:#010x}  ts={:#010x}",
                entry.dll_base() as usize,
                entry.size_of_image(),
                entry.entry_point() as usize,
                entry.flags(),
                entry.time_date_stamp(),
            );
            if i == 1 {
                ntdll = entry.dll_base();
            }
        }
        if !ntdll.is_null() {
            let export_ntdll = ExportTable::new(ntdll);
            match export_ntdll {
                Some(export_ntdll) => {
                    for entry in export_ntdll.entries {
                        if unique_hash(entry.name.as_deref().unwrap_or_default()) == 0x97c4468 {
                            println!("strcpy found at RVA: {:#x}", entry.va as usize);
                            break;
                        }
                    }
                }
                None => {
                    println!("Invalid Export Table");
                }
            }
        }

        println!("\n--- GetNtdllBase ---");
        println!("ntdll base: {:#x}", get_ntdll_base() as usize);
        println!(
            "{}",
            get_export_by_name(get_ntdll_base(), "strcpy").unwrap() as usize
        );
        let src = b"hola\0";
        let mut dst = [0u8; 10];
        let args = [dst.as_mut_ptr() as usize, src.as_ptr() as usize];
        let x = call_cdecl(
            get_export_by_name(get_ntdll_base(), "strcpy").unwrap(),
            &args,
        );
        println!("{}", String::from_utf8_lossy(&dst));
        println!("{}", x);
    }
    let hash = 0x2759addf;
    let nt_allocate_virtual_memory_with_hash =
        get_export_by_name_hash(unsafe { get_ntdll_base() }, hash);
    match nt_allocate_virtual_memory_with_hash {
        Ok(address) => println!(
            "nt_allocate_virtual_memory found at RVA: {:#x}",
            address as usize
        ),
        Err(_) => println!("nt_allocate_virtual_memory not found"),
    }
    let nt_delay_execution_ssn: u32 = 0x0034;

    let segundos = 3;
    let mut delay_interval: i64 = -(segundos * 10_000_000);

    println!("Iniciando la congelacion de {} segundos.", segundos);

    unsafe {
        let status = direct_syscall_6(
            nt_delay_execution_ssn,
            0,
            &mut delay_interval as *mut i64 as usize,
            0,
            0,
            0,
            0,
        );

        if status == 0 {
            println!("bien");
        } else {
            println!("mal, status: 0x{:X}", status);
        }
    }
    println!("Iniciando la congelacion de {} segundos.", segundos);

    unsafe {
        let status = indirect_syscall_6(
            unique_hash("NtDelayExecution"),
            nt_delay_execution_ssn,
            0,
            &mut delay_interval as *mut i64 as usize,
            0,
            0,
            0,
            0,
        );

        match status {
            Ok(0) => println!("bien"),
            Ok(val) => println!("mal, status: 0x{:X}", val),
            Err(err) => println!("Error al ejecutar la syscall: {}", err),
        }
    }
}
