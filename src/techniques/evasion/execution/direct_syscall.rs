#[cfg(target_arch = "x86_64")]
pub unsafe fn direct_syscall_6(
    sys_number: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> i32 {
    let mut status: i32;
    use std::arch::asm;

    unsafe {
        asm!(
            "mov r10, rcx",
            "sub rsp, 0x28",
            "mov [rsp + 0x20], {a5}",
            "mov [rsp + 0x28], {a6}",
            "mov eax, edi",
            "syscall",
            "add rsp, 0x28",

            in("edi") sys_number,
            in("rcx") a1,
            in("rdx") a2,
            in("r8")  a3,
            in("r9")  a4,
            a5 = in(reg) a5,
            a6 = in(reg) a6,
            lateout("eax") status,
            clobber_abi("win64")
        );
    }
    status
}

#[cfg(target_arch = "x86")]
pub unsafe fn direct_syscall_6(
    sys_number: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> i32 {
    let mut status: i32;
    use std::arch::asm;
    let args = [a1, a2, a3, a4, a5, a6];

    unsafe {
        asm!(

            "push dword ptr [{args_ptr} + 20]",
            "push dword ptr [{args_ptr} + 16]",
            "push dword ptr [{args_ptr} + 12]",
            "push dword ptr [{args_ptr} + 8]",
            "push dword ptr [{args_ptr} + 4]",
            "push dword ptr [{args_ptr}]",

            "mov edx, esp",

            "mov eax, {sys_num}",
            "sysenter",

            "add esp, 24",

            sys_num = in(reg) sys_number,
            args_ptr = in(reg) args.as_ptr(),
            lateout("eax") status
        );
    }
    status
}
