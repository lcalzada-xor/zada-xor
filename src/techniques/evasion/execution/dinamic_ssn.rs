use crate::techniques::evasion::dinamic_api_resolution::{get_export_by_name_hash, get_ntdll_base};

#[cfg(target_arch = "x86_64")] //solo para x64
pub fn get_dinamic_ssn(api_hash: u32) -> Result<u32, String> {
    let base_addr = unsafe { get_ntdll_base() }.expect("Failed to locate NTDLL base address");
    let api_addr = get_export_by_name_hash(base_addr, api_hash)
        .map_err(|e| format!("Failed to resolve API with hash {:#08x}: {}", api_hash, e))?;

    let mut offset = 0;

    loop {
        let current_addr = unsafe { api_addr.add(offset) };
        if unsafe {
            *current_addr == 0xCC && *current_addr.add(1) == 0xCC && *current_addr.add(2) == 0xCC
        } {
            return Err(format!("Separador INT3 (0xCC) detectado sin averiguar ssn"));
        }
        if unsafe { *current_addr == 0x90 && *current_addr.add(1) == 0x90 } {
            return Err(format!("Separador NOP (0x90) detectado sin averiguar ssn"));
        }
        // 0xB8 mov eax
        if unsafe { *current_addr } == 0xB8 {
            // antes tiene que estar"mov r10, rcx" (4C 8B D1)
            {
                if offset >= 3
                    && unsafe { *current_addr.sub(3) } == 0x4C
                    && unsafe { *current_addr.sub(2) } == 0x8B
                    && unsafe { *current_addr.sub(1) } == 0xD1
                {
                    let syscall_number =
                        unsafe { (current_addr.add(1) as *const u32).read_unaligned() };

                    return Ok(syscall_number);
                }
            }
        }
        offset += 1;
        if offset > 0x1000 {
            return Err(format!(
                "Límite de seguridad alcanzado al recorrer la api sin averiguar ssn."
            ));
        }
    }
}
