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
    // en arquitectura de 32 bits el ret limpia el stack con el num de args que tiene la funcion de ntdll,
    // es por ello que si metes mas args que los que tiene la funcion hay un error, por ello este mounstruo de funcion
    // en cambio en 64 bits el encargado de limpiar el stack es el caller
    #[cfg(target_arch = "x86")]
    unsafe {
        match args.len() {
            0 => {
                let f: unsafe extern "C" fn() -> isize = std::mem::transmute(func_ptr);
                f()
            }
            1 => {
                let f: unsafe extern "C" fn(usize) -> isize = std::mem::transmute(func_ptr);
                f(args[0])
            }
            2 => {
                let f: unsafe extern "C" fn(usize, usize) -> isize = std::mem::transmute(func_ptr);
                f(args[0], args[1])
            }
            3 => {
                let f: unsafe extern "C" fn(usize, usize, usize) -> isize =
                    std::mem::transmute(func_ptr);
                f(args[0], args[1], args[2])
            }
            4 => {
                let f: unsafe extern "C" fn(usize, usize, usize, usize) -> isize =
                    std::mem::transmute(func_ptr);
                f(args[0], args[1], args[2], args[3])
            }
            5 => {
                let f: unsafe extern "C" fn(usize, usize, usize, usize, usize) -> isize =
                    std::mem::transmute(func_ptr);
                f(args[0], args[1], args[2], args[3], args[4])
            }
            6 => {
                let f: unsafe extern "C" fn(usize, usize, usize, usize, usize, usize) -> isize =
                    std::mem::transmute(func_ptr);
                f(args[0], args[1], args[2], args[3], args[4], args[5])
            }
            7 => {
                let f: unsafe extern "C" fn(usize, usize, usize, usize, usize, usize, usize) -> isize =
                    std::mem::transmute(func_ptr);
                f(
                    args[0], args[1], args[2], args[3], args[4], args[5], args[6],
                )
            }
            8 => {
                let f: unsafe extern "C" fn(
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                ) -> isize = std::mem::transmute(func_ptr);
                f(
                    args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
                )
            }
            9 => {
                let f: unsafe extern "C" fn(
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                ) -> isize = std::mem::transmute(func_ptr);
                f(
                    args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
                )
            }
            _ => {
                let f: CdeclCall = std::mem::transmute(func_ptr);
                let (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) = unpack(args);
                f(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
            }
        }
    }

    #[cfg(not(target_arch = "x86"))]
    unsafe {
        let f: CdeclCall = std::mem::transmute(func_ptr);
        let (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) = unpack(args);
        f(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
    }
}

/// Llama funciones stdcall: WinAPI (VirtualAlloc, NtAllocateVirtualMemory...).
/// En x64 es equivalente a call_cdecl.
pub unsafe fn call_stdcall(func_ptr: *const u8, args: &[usize]) -> isize {
    #[cfg(target_arch = "x86")]
    unsafe {
        match args.len() {
            0 => {
                let f: unsafe extern "system" fn() -> isize = std::mem::transmute(func_ptr);
                f()
            }
            1 => {
                let f: unsafe extern "system" fn(usize) -> isize = std::mem::transmute(func_ptr);
                f(args[0])
            }
            2 => {
                let f: unsafe extern "system" fn(usize, usize) -> isize =
                    std::mem::transmute(func_ptr);
                f(args[0], args[1])
            }
            3 => {
                let f: unsafe extern "system" fn(usize, usize, usize) -> isize =
                    std::mem::transmute(func_ptr);
                f(args[0], args[1], args[2])
            }
            4 => {
                let f: unsafe extern "system" fn(usize, usize, usize, usize) -> isize =
                    std::mem::transmute(func_ptr);
                f(args[0], args[1], args[2], args[3])
            }
            5 => {
                let f: unsafe extern "system" fn(usize, usize, usize, usize, usize) -> isize =
                    std::mem::transmute(func_ptr);
                f(args[0], args[1], args[2], args[3], args[4])
            }
            6 => {
                let f: unsafe extern "system" fn(
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                ) -> isize = std::mem::transmute(func_ptr);
                f(args[0], args[1], args[2], args[3], args[4], args[5])
            }
            7 => {
                let f: unsafe extern "system" fn(
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                ) -> isize = std::mem::transmute(func_ptr);
                f(
                    args[0], args[1], args[2], args[3], args[4], args[5], args[6],
                )
            }
            8 => {
                let f: unsafe extern "system" fn(
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                ) -> isize = std::mem::transmute(func_ptr);
                f(
                    args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
                )
            }
            9 => {
                let f: unsafe extern "system" fn(
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                ) -> isize = std::mem::transmute(func_ptr);
                f(
                    args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
                )
            }
            _ => {
                let f: StdcallCall = std::mem::transmute(func_ptr);
                let (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) = unpack(args);
                f(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
            }
        }
    }
    #[cfg(not(target_arch = "x86"))]
    unsafe {
        let f: StdcallCall = std::mem::transmute(func_ptr);
        let (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) = unpack(args);
        f(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
    }
}
