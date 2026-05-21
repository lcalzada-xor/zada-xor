//! Módulo que define constantes de referencia para los códigos de syscall (System Service Numbers / SSNs)
//! de las funciones nativas de Windows (`Nt*`/`Zw*`) más comúnmente utilizadas.
//!
//! # ADVERTENCIA IMPORTANTE
//! Los números de syscall (SSNs) no son estables y cambian entre diferentes versiones,
//! service packs, y compilaciones (builds) de Windows. Hardcodear estos valores es inestable y
//! puede provocar fallos catastróficos o comportamientos inesperados tras una actualización del sistema.
//!
//! Estas constantes se proporcionan con fines de **REFERENCIA académica y educativa**
//! (basadas principalmente en **Windows 10 x64, build 19041+ / 20H2+**).
//!
//! En sistemas de producción o proyectos avanzados de ingeniería de software a bajo nivel, se recomienda
//! resolver estos números de manera **DINÁMICA** en tiempo de ejecución (por ejemplo, analizando el Export
//! Address Table (EAT) de la librería `ntdll.dll` cargada en el espacio de direcciones del proceso y
//! decodificando las instrucciones de la cabecera de la función (`mov eax, SSN`), o utilizando técnicas
//! como *Hell's Gate* / *Halo's Gate* para evadir ganchos de EDR/AV).

/// Syscall de asignación de memoria virtual (NtAllocateVirtualMemory).
/// Común en Windows 10 build 19041+ x64: `0x0018` (24 decimal).
pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x0018;

/// Syscall de liberación de memoria virtual (NtFreeVirtualMemory).
/// Común en Windows 10 build 19041+ x64: `0x001E` (30 decimal).
pub const NT_FREE_VIRTUAL_MEMORY: u32 = 0x001E;

/// Syscall para modificar la protección de páginas de memoria virtual (NtProtectVirtualMemory).
/// Común en Windows 10 build 19041+ x64: `0x0050` (80 decimal).
pub const NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x0050;

/// Syscall para escribir memoria virtual en otro proceso (NtWriteVirtualMemory).
/// Común en Windows 10 build 19041+ x64: `0x003A` (58 decimal).
pub const NT_WRITE_VIRTUAL_MEMORY: u32 = 0x003A;

/// Syscall para leer memoria virtual de otro proceso (NtReadVirtualMemory).
/// Común en Windows 10 build 19041+ x64: `0x003F` (63 decimal).
pub const NT_READ_VIRTUAL_MEMORY: u32 = 0x003F;

/// Syscall para consultar atributos de páginas de memoria virtual (NtQueryVirtualMemory).
/// Común en Windows 10 build 19041+ x64: `0x0023` (35 decimal).
pub const NT_QUERY_VIRTUAL_MEMORY: u32 = 0x0023;

/// Syscall para abrir un manejador (handle) a un proceso existente (NtOpenProcess).
/// Común en Windows 10 build 19041+ x64: `0x0026` (38 decimal).
pub const NT_OPEN_PROCESS: u32 = 0x0026;

/// Syscall para terminar la ejecución de un proceso (NtTerminateProcess).
/// Común en Windows 10 build 19041+ x64: `0x002C` (44 decimal).
pub const NT_TERMINATE_PROCESS: u32 = 0x002C;

/// Syscall para crear un hilo de ejecución en otro proceso (NtCreateThreadEx).
/// Común en Windows 10 build 19041+ x64: `0x00C1` (193 decimal).
/// *Nota*: Este valor es de los más propensos a cambiar entre variantes menores de Windows 10/11.
pub const NT_CREATE_THREAD_EX: u32 = 0x00C1;

/// Syscall para mapear una vista de una sección en el espacio de direcciones de un proceso (NtMapViewOfSection).
/// Común en Windows 10 build 19041+ x64: `0x0028` (40 decimal).
pub const NT_MAP_VIEW_OF_SECTION: u32 = 0x0028;

/// Syscall para desmapear una vista de una sección en un proceso (NtUnmapViewOfSection).
/// Común en Windows 10 build 19041+ x64: `0x002A` (42 decimal).
pub const NT_UNMAP_VIEW_OF_SECTION: u32 = 0x002A;

/// Syscall para cerrar un manejador de objeto del kernel (NtClose).
/// Común en Windows 10 build 19041+ x64: `0x000F` (15 decimal).
pub const NT_CLOSE: u32 = 0x000F;
