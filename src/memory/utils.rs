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
