use zada_xor::cipher::communication::SecureDataPacket;
use zada_xor::cipher::handshake::*;
use zada_xor::cipher::keys::Identity;
use zada_xor::memory::process::close_process::*;
use zada_xor::memory::process::open_process::*;
use zada_xor::memory::process::protect_virtual_mem::*;
use zada_xor::memory::process::query_virtual_mem::*;
use zada_xor::memory::process::read_process_mem::nt_read_virtual_memory;
use zada_xor::memory::process::write_process_mem::nt_write_virtual_memory;
use zada_xor::structures::pe::export::ExportTable;
use zada_xor::structures::pe::headers::PeHeaderInfo;
use zada_xor::structures::peb::ldr::PebLdrData;
use zada_xor::structures::peb::ldr_entry::LdrDataTableEntry;
#[cfg(target_arch = "x86_64")]
use zada_xor::structures::peb::ldr_entry::offsets::x64_win10 as ldr_off;
#[cfg(target_arch = "x86")]
use zada_xor::structures::peb::ldr_entry::offsets::x86_win10 as ldr_off;
use zada_xor::structures::peb::list_entry::ListEntry;
use zada_xor::structures::peb::peb::Peb;
use zada_xor::techniques::discovery::process::*;
use zada_xor::techniques::evasion::api_hashing::*;
use zada_xor::techniques::evasion::dinamic_api_resolution::*;
use zada_xor::techniques::evasion::execution::dinamic_ssn::*;
use zada_xor::techniques::evasion::execution::direct_syscall::*;
use zada_xor::techniques::evasion::execution::dynamic_call::*;
use zada_xor::techniques::evasion::execution::indirect_syscall::*;

fn main() {
    println!("Obteniendo dir base de ntdll...");
    let ntdll_base_addr =
        unsafe { get_ntdll_base().expect("Failed to get ntdll.dll base address") };
    println!("Dir base de ntdll: {:#x}", ntdll_base_addr as usize);

    let headers = unsafe { PeHeaderInfo::parse_headers(ntdll_base_addr) }
        .expect("Failed to parse PE headers");
    println!("Headers PE: {:#x}", headers.optional_header_ptr as usize);
    let identity_server = Identity::new();
    let identity_client = Identity::new();

    let (client_handshake_packet, simetric_key_for_client) = SecureClientHandshakePacket::new(
        identity_server.public_key.to_bytes(),
        identity_client.public_key.to_bytes(),
    );
    let self_pid = std::process::id();
    println!("self_pid: {}", self_pid);
    println!("ntdll.dll: {:#x}", unique_hash("ntdll.dll"));
    println!("kernel32.dll: {:#x}", unique_hash("kernel32.dll"));
    let handle = match open_process(
        self_pid,
        DESIRED_ACCESS::PROCESS_VM_READ
            | DESIRED_ACCESS::PROCESS_VM_WRITE
            | DESIRED_ACCESS::PROCESS_QUERY_INFORMATION
            | DESIRED_ACCESS::PROCESS_VM_OPERATION,
    ) {
        Ok(handl) => handl,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };
    println!("handle: {:#?}", handle);
    escanear_memoria_proceso(handle);

    let mut buffer_dinamico = String::with_capacity(32);
    buffer_dinamico.push_str("RustInternals123");

    let direccion_memoria = buffer_dinamico.as_ptr() as usize;
    let tamano_a_leer = 16;
    match nt_read_virtual_memory(handle, direccion_memoria, tamano_a_leer) {
        Ok(bytes_leidos) => {
            if let Ok(texto_recuperado) = std::str::from_utf8(&bytes_leidos) {
                println!("[+] ¡ÉXITO! Bytes leídos correctamente.");
                println!(
                    "[+] Contenido recuperado de la memoria: {}",
                    texto_recuperado
                );
            } else {
                println!(
                    "[!] Se leyeron los bytes pero no son un texto válido: {:?}",
                    bytes_leidos
                );
            }
        }
        Err(e) => {
            println!("[!] La prueba falló. Motivo: {}", e);
        }
    }
    let texto_a_escribir = "Terobolavariable";
    match nt_write_virtual_memory(handle, direccion_memoria, texto_a_escribir.as_bytes()) {
        Ok(bytes_escritos) => {
            println!("[+] ¡ÉXITO! Bytes escritos correctamente.");
            println!("[+] Bytes escritos: {}", bytes_escritos);
        }
        Err(e) => {
            println!("[!] La prueba falló. Motivo: {}", e);
        }
    }
    println!("VOlviendo a leer la variable ...");
    match nt_read_virtual_memory(handle, direccion_memoria, tamano_a_leer) {
        Ok(bytes_leidos) => {
            if let Ok(texto_recuperado) = std::str::from_utf8(&bytes_leidos) {
                println!("[+] ¡ÉXITO! Bytes leídos correctamente.");
                println!(
                    "[+] Contenido recuperado de la memoria: {}",
                    texto_recuperado
                );
            } else {
                println!(
                    "[!] Se leyeron los bytes pero no son un texto válido: {:?}",
                    bytes_leidos
                );
            }
        }
        Err(e) => {
            println!("[!] La prueba falló. Motivo: {}", e);
        }
    }
    match nt_protect_virtual_memory(
        handle,
        direccion_memoria,
        tamano_a_leer,
        MemoryProtection::ExecuteReadWrite,
    ) {
        Ok(_) => {
            println!("[+] ¡ÉXITO! Permisos de la región de memoria cambiados correctamente.");
        }
        Err(e) => {
            println!("[!] La prueba falló. Motivo: {}", e);
        }
    }
    escanear_memoria_proceso(handle);
    match nt_close(handle) {
        Ok(_) => {
            println!("[+] ¡ÉXITO! Handle cerrado correctamente.");
        }
        Err(e) => {
            println!("[!] La prueba falló. Motivo: {}", e);
        }
    }

    println!("---------------------------------");

    println!("Simetric key for client: {:?}", simetric_key_for_client.key);
    println!("------------------------------------------");
    let (symmetric_key_for_server, _trash_pub_key_server) =
        match client_handshake_packet.process_packet(&identity_server.private_key) {
            Ok((symmetric_key, pub_key)) => (symmetric_key, pub_key),
            Err(e) => {
                println!("Error: {}", e);
                return;
            }
        };
    println!(
        "Simetric key for server: {:?}",
        symmetric_key_for_server.key
    );
    println!("----------------------------------");
    println!("Simulacion de envio de paquetes");
    let data = SecureDataPacket::cipher(
        "Hola esto es un mensaje que va a ir cifrado".as_bytes(),
        &simetric_key_for_client,
    );
    println!("Mensaje cifrado : {:#?}", data.payload);

    let data_received = SecureDataPacket::decipher(&data.payload, &simetric_key_for_client)
        .expect("Error al descifrar el mensaje");
    println!(
        "Mensaje descifrado : {}",
        String::from_utf8_lossy(&data_received)
    );
    println!("----------------------------------");

    println!("Simulacion de envio de paquetes alterados");

    let mut data_alterado = data.payload;
    data_alterado[0] = 0;
    let data_received_alterado =
        SecureDataPacket::decipher(&data_alterado, &simetric_key_for_client);
    println!("Mensaje descifrado : {:#?}", data_received_alterado);
    println!("----------------------------------");

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

        let segundos = 3;
        println!(
            "Iniciando la congelacion de {} segundos mediante dynamic_stdcall_by_name.",
            segundos
        );

        let mut delay_interval: i64 = -(segundos * 10_000_000);
        match dynamic_stdcall_by_name(
            "NtDelayExecution",
            &[0, &mut delay_interval as *mut i64 as usize],
        ) {
            Ok(_) => println!("Congelacion completada con exito."),
            Err(e) => println!("Error al congelar: {}", e),
        }

        println!("\n--- Process Discovery ---");
        match process_discovery() {
            Ok(processes) => {
                println!(
                    "┌──────────┬──────────┬──────────┬──────────┬──────────┬────────────────┬─────────────────────────────────────┐"
                );
                println!(
                    "│ {:^8} │ {:^8} │ {:^8} │ {:^8} │ {:^8} │ {:^14} │ {:<35} │",
                    "PID", "PPID", "Session", "Threads", "Handles", "Working Set", "Process Name"
                );
                println!(
                    "├──────────┼──────────┼──────────┼──────────┼──────────┼────────────────┼─────────────────────────────────────┤"
                );
                for proc in &processes {
                    let formatted_ws = format_bytes(proc.working_set_size);
                    let name = if proc.name.len() > 35 {
                        format!("{}...", &proc.name[..32])
                    } else {
                        proc.name.clone()
                    };
                    println!(
                        "│ {:<8} │ {:<8} │ {:<8} │ {:<8} │ {:<8} │ {:>14} │ {:<35} │",
                        proc.pid,
                        proc.parent_pid,
                        proc.session_id,
                        proc.threads_count,
                        proc.handle_count,
                        formatted_ws,
                        name
                    );
                }
                println!(
                    "└──────────┴──────────┴──────────┴──────────┴──────────┴────────────────┴─────────────────────────────────────┘"
                );
            }
            Err(e) => println!("Error al ejecutar la syscall: {}", e),
        }
        println!("--- Fin del discovery ---\n");

        println!("\n--- GetNtdllBase ---");
        let ntdll_base = get_ntdll_base().expect("Failed to locate NTDLL base address");
        println!("ntdll base: {:#x}", ntdll_base as usize);
        println!(
            "strcpy address: {:#x}",
            get_export_by_name(ntdll_base, "strcpy").unwrap() as usize
        );
        let src = b"hola\0";
        let mut dst = [0u8; 10];
        let args = [dst.as_mut_ptr() as usize, src.as_ptr() as usize];
        match dynamic_cdecl_by_name("strcpy", &args) {
            Ok(_) => println!("{}", String::from_utf8_lossy(&dst)),
            Err(e) => println!("Error al ejecutar strcpy: {}", e),
        }
    }

    println!(
        "\nHash NtQuerySystemInformation: {:#x}",
        unique_hash("NtQuerySystemInformation")
    );

    let hash = 0x2759addf;
    let nt_allocate_virtual_memory_with_hash = unsafe {
        get_export_by_name_hash(
            get_ntdll_base().expect("Failed to locate NTDLL base address"),
            hash,
        )
        .expect("Failed to resolve NtAllocateVirtualMemory")
    };
    println!(
        "nt_allocate_virtual_memory found at RVA: {:#x}",
        nt_allocate_virtual_memory_with_hash as usize
    );
    let nt_delay_execution_ssn: u32 = 0x0034;

    let segundos = 10;
    let mut delay_interval: i64 = -(segundos * 10_000_000);
    println!("Iniciando la congelacion de {} segundos directa.", segundos);
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

    println!("\n--- Get Dynamic SSN ---");
    let ssn_code = match get_dinamic_ssn(unique_hash("NtDelayExecution")) {
        Ok(ssn) => ssn,
        Err(e) => panic!("Error al obtener el SSN: {}", e),
    };
    println!("SSN: {:#x}", ssn_code);

    println!(
        "Iniciando la congelacion de {} segundos indirecta.",
        segundos
    );

    unsafe {
        let status = indirect_syscall_6(
            unique_hash("NtDelayExecution"),
            ssn_code,
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

fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return "0 B".to_string();
    }
    let units = ["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < units.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    format!("{:.2} {}", size, units[unit_idx])
}
