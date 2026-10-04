# Zada-Xor: Manual de Referencia Técnica y Arquitectura Interna de Windows NT

> **Idiomas / Languages:** **Español** | [English](README.md)

**Zada-Xor** es un entorno de investigación en ingeniería inversa, análisis forense de memoria y seguridad ofensiva/defensiva implementado íntegramente en Rust. Su propósito fundamental reside en la interacción directa con el subsistema nativo de Windows NT (`ntoskrnl.exe` / `ntdll.dll`) en modo usuario (Ring 3), prescindiendo absolutamente de las bibliotecas de abstracción provistas por Microsoft para Rust (`windows`, `windows-sys` o `winapi`) y de parsers PE de terceros.

El proyecto implementa desde cero primitivas para el análisis manual de estructuras ejecutables PE/PE32+, la navegación indetectable de las listas del cargador en el Bloque de Entorno del Proceso (PEB), la resolución dinámica de identificadores de servicios del sistema (SSN) mediante técnicas avanzadas de desmontaje en memoria (Hell's Gate / Halo's Gate), el despacho de llamadas indirectas al sistema (*Indirect Syscalls*) combinadas con falsificación sintética de la pila de llamadas (*Call Stack Spoofing*), y un canal criptográfico de grado de producción basado en el intercambio de claves Diffie-Hellman en Curve25519 y cifrado autenticado simétrico AEAD ChaCha20-Poly1305.

---

## Descargo de Responsabilidad y Uso Ético (Disclaimer)

> [!IMPORTANT]
> **Este repositorio ha sido concebido y desarrollado con fines estrictamente educativos, de investigación académica y para el avance de la seguridad defensiva.**
>
> * **Ámbito Autorizado:** El código fuente, los binarios compilados y la documentación técnica contenida en este proyecto están destinados exclusivamente a la experimentación en laboratorios controlados, entornos de virtualización aislados y auditorías donde exista un consentimiento previo, explícito y formal por escrito de los propietarios de los sistemas.
> * **Enfoque de Seguridad Defensiva:** Las técnicas documentadas detallan los vectores utilizados por amenazas persistentes avanzadas (APTs) y malware de última generación para evadir ganchos de monitorización en espacio de usuario. Su análisis tiene como fin permitir a investigadores de seguridad, desarrolladores de plataformas EDR/XDR, analistas de SOC e ingenieros de detección comprender la mecánica subyacente y diseñar reglas de correlación, telemetría a nivel de kernel (ETW-Ti) y firmas de comportamiento efectivas.
> * **Prohibición de Uso Ilícito:** El autor no respalda, promueve ni asume responsabilidad alguna por el uso indebido, destructivo o malicioso que terceros pudieran realizar con este material. La ejecución de estas técnicas contra infraestructura no autorizada constituye una violación de los marcos legales aplicables.

> [!WARNING]
> La manipulación directa de estructuras internas de Windows (`PEB`, `TEB`, `LDR`) y la ejecución de llamadas al sistema indirectas implican asunciones de arquitectura que pueden variar entre compilaciones del kernel. Aunque el framework incluye soporte dinámico para versiones desde Windows Vista hasta Windows 11 25H2, la alteración descontrolada de la memoria de procesos puede provocar inestabilidad o corrupción del proceso anfitrión.

---

## Tabla de Contenidos

- [Descargo de Responsabilidad y Uso Ético (Disclaimer)](#descargo-de-responsabilidad-y-uso-ético-disclaimer)
- [Filosofía Arquitectónica: Zero-Dependency Runtime](#filosofía-arquitectónica-zero-dependency-runtime)
- [Estructura y Mapeo del Repositorio](#estructura-y-mapeo-del-repositorio)
- [Estructuras de Bajo Nivel (`src/structures/`)](#estructuras-de-bajo-nivel-srcstructures)
  - [Parsing Manual del Formato PE (`src/structures/pe/`)](#parsing-manual-del-formato-pe-srcstructurespe)
  - [Introspección del Runtime TEB / PEB / LDR (`src/structures/peb/`)](#introspección-del-runtime-teb--peb--ldr-srcstructurespeb)
    - [Obtención del PEB sin APIs del Sistema](#obtención-del-peb-sin-apis-del-sistema)
    - [Detección Dinámica de la Versión del Sistema Operativo](#detección-dinámica-de-la-versión-del-sistema-operativo)
    - [Comparativa de Offsets del PEB en x64 (`peb_x64.rs`)](#comparativa-de-offsets-del-peb-en-x64-peb_x64rs)
    - [Estructuras del Cargador (`_PEB_LDR_DATA` y `_LDR_DATA_TABLE_ENTRY`)](#estructuras-del-cargador-_peb_ldr_data-y-_ldr_data_table_entry)
    - [Navegación Circular con `_LIST_ENTRY` y Trait `Iterator`](#navegación-circular-con-_list_entry-y-trait-iterator)
- [Subsistema Nativo NT (`src/nt/`)](#subsistema-nativo-nt-srcnt)
  - [Tipos del Kernel NT (`src/nt/types.rs`)](#tipos-del-kernel-nt-srcnttypesrs)
  - [Gestión de Procesos (`src/nt/process/`)](#gestión-de-procesos-srcntprocess)
    - [`open_process.rs`](#open_processrs)
    - [`query_information_process.rs`](#query_information_processrs)
  - [Gestión de Objetos del Kernel (`src/nt/kernel_objects/`)](#gestión-de-objetos-del-kernel-srcntkernel_objects)
    - [`close.rs`](#closers)
    - [`query_object.rs`](#query_objectrs)
    - [`duplicate_object.rs`](#duplicate_objectrs)
  - [Gestión Avanzada de Memoria Virtual (`src/nt/memory/`)](#gestión-avanzada-de-memoria-virtual-srcntmemory)
    - [`virtual_alloc.rs`](#virtual_allocrs)
    - [`read_process_mem.rs` y `write_process_mem.rs`](#read_process_memrs-y-write_process_memrs)
    - [`protect_virtual_mem.rs`](#protect_virtual_memrs)
    - [`query_virtual_mem.rs`](#query_virtual_memrs)
    - [`pattern_scan_mem.rs`: Escaneo de Patrones y Delimitación mediante `.pdata`](#pattern_scan_memrs-escaneo-de-patrones-y-delimitación-mediante-pdata)
- [Técnicas de Evasión y Descubrimiento (`src/techniques/`)](#técnicas-de-evasión-y-descubrimiento-srctechniques)
  - [API Hashing y Ofuscación Estática (`src/techniques/evasion/api_hashing.rs`)](#api-hashing-y-ofuscación-estática-srctechniquesevasionapi_hashingrs)
    - [Constantes y Hashes Precalculados](#constantes-y-hashes-precalculados)
  - [Resolución Dinámica de APIs (`src/techniques/evasion/dinamic_api_resolution.rs`)](#resolución-dinámica-de-apis-srctechniquesevasiondinamic_api_resolutionrs)
  - [Extracción Dinámica de SSN: Hell's Gate y Halo's Gate (`src/techniques/evasion/execution/dinamic_ssn.rs`)](#extracción-dinámica-de-ssn-hells-gate-y-halos-gate-srctechniquesevasionexecutiondinamic_ssnrs)
  - [Despacho de Syscalls Directas (`src/techniques/evasion/execution/direct_syscall.rs`)](#despacho-de-syscalls-directas-srctechniquesevasionexecutiondirect_syscallrs)
- [Evasión Avanzada: Indirect Syscalls y Call Stack Spoofing](#evasión-avanzada-indirect-syscalls-y-call-stack-spoofing)
  - [Salto Indirecto a `ntdll.dll`](#salto-indirecto-a-ntdlldll)
  - [Falsificación de la Pila de Llamadas (Call Stack Spoofing)](#falsificación-de-la-pila-de-llamadas-call-stack-spoofing)
    - [1. Decodificación de `.pdata` y `UNWIND_INFO` (`unwind_info.rs`)](#1-decodificación-de-pdata-y-unwind_info-unwind_infors)
    - [2. Localización de Gadgets en NTDLL](#2-localización-de-gadgets-en-ntdll)
    - [3. Estructura Sintética de la Pila en Ejecución](#3-estructura-sintética-de-la-pila-en-ejecución)
- [Técnicas Complementarias de Invocación y Memoria](#técnicas-complementarias-de-invocación-y-memoria)
  - [Inyección de Memoria Sigilosa RW $\rightarrow$ RX (`write_process_mem_rw_rx.rs`)](#inyección-de-memoria-sigilosa-rw-rightarrow-rx-write_process_mem_rw_rxrs)
  - [Envoltorios de Invocación Dinámica (`dynamic_call.rs` y `normal_call.rs`)](#envoltorios-de-invocación-dinámica-dynamic_callrs-y-normal_callrs)
  - [Descubrimiento e Introspección de Procesos (`src/techniques/discovery/process.rs`)](#descubrimiento-e-introspección-de-procesos-srctechniquesdiscoveryprocessrs)
- [Subsistema Criptográfico y Canal Seguro (`src/cipher/`)](#subsistema-criptográfico-y-canal-seguro-srccipher)
  - [Gestión de Identidad Asimétrica (`keys.rs`)](#gestión-de-identidad-asimétrica-keysrs)
  - [Cifrado Simétrico Autenticado AEAD ChaCha20-Poly1305 (`cipher_data.rs`)](#cifrado-simétrico-autenticado-aead-chacha20-poly1305-cipher_datars)
    - [Estructura del Sobre de Datos (Payload Envelope)](#estructura-del-sobre-de-datos-payload-envelope)
  - [Protocolo de Handshake con Anonimización de Clave (`handshake.rs`)](#protocolo-de-handshake-con-anonimización-de-clave-handshakers)
- [Binarios de Demostración y Validación (`src/bin/`)](#binarios-de-demostración-y-validación-srcbin)
  - [1. `src/bin/prueba.rs`: Suite Integral de 25 Pasos](#1-srcbinpruebars-suite-integral-de-25-pasos)
  - [2. `src/bin/prueba_call_spoofing.rs`: PoC Especializada](#2-srcbinprueba_call_spoofingrs-poc-especializada)
- [Compilación, Optimización y Entornos de Laboratorio](#compilación-optimización-y-entornos-de-laboratorio)
  - [Perfil de Optimización en `Cargo.toml`](#perfil-de-optimización-en-cargotoml)
  - [Compilación Cruzada (Cross-Compilation para Windows)](#compilación-cruzada-cross-compilation-para-windows)
  - [Ejecución en Laboratorio con Wine](#ejecución-en-laboratorio-con-wine)
- [Matriz Resumen de Archivos y Componentes](#matriz-resumen-de-archivos-y-componentes)

---

## Filosofía Arquitectónica: Zero-Dependency Runtime

Una de las características determinantes de `zada-xor` es su arquitectura **independiente y autónoma**:

1. **Ausencia de SDKs Externos de Windows:** El proyecto no utiliza `winapi`, `windows-sys` ni `windows`. Toda interacción con el sistema operativo, desde la obtención del puntero al TEB mediante registros de segmento hasta el despacho de llamadas nativas, se implementa mediante definiciones de tipos C (`#[repr(C)]`), desreferenciaciones sin alinear (`read_unaligned`) y ensamblador en línea (`core::arch::asm!`).
2. **Sin Parsers PE Externos:** Las estructuras de cabeceras DOS, NT, Directorios de Datos, Tablas de Exportación y Tablas de Excepciones (`.pdata`) son analizadas directamente sobre los bytes mapeados en memoria mediante punteros crudos.
3. **Dependencias Criptográficas Estrictamente Acotadas:** El archivo `Cargo.toml` restringe las dependencias externas a únicamente tres crates criptográficos especializados para el canal de comunicaciones:
   - `x25519-dalek` (v2.0.1): Primitivas en Rust puro para el intercambio de claves Diffie-Hellman en Curve25519.
   - `rand_core` (v0.6.4): Abstracción para el consumo del generador de entropía segura del sistema operativo.
   - `chacha20poly1305` (v0.10): Implementación del cifrado de flujo autenticado AEAD (RFC 8439).

> [!NOTE]
> **Reflexión del autor sobre el diseño Zero-Dependency:**
> Mi objetivo principal al estructurar el proyecto fue eliminar cualquier huella predecible en la Import Address Table (IAT) y en los metadatos del binario. Cuando un analista o un motor de detección examina un binario en Rust convencional, suele encontrar decenas de dependencias y cadenas reveladoras introducidas por los SDKs estándar. Al prescindir de bibliotecas externas y construir manualmente cada estructura desde los registros de segmento `GS`/`FS`, el binario resultante no depende de DLLs intermedias y opera en contacto directo con el subsistema nativo del núcleo.

---

## Estructura y Mapeo del Repositorio

La arquitectura del proyecto está organizada en cinco subsistemas modulares bajo `src/`:

```text
zada-xor/
├── Cargo.toml                              # Configuración de compilación, crates y optimizaciones de release
├── comandos                                # Scripts de compilación cruzada y ejecución en prefijos Wine
├── src/
│   ├── lib.rs                              # Raíz de biblioteca; reexportación de módulos públicos
│   ├── utils.rs                            # Primitivas de lectura no alineada y manejo de cadenas Unicode
│   ├── bin/                                # Binarios ejecutables de demostración y validación
│   │   ├── prueba.rs                       # Suite integral secuencial de validación de 25 pasos
│   │   └── prueba_call_spoofing.rs         # PoC especializada de indirect syscall y call stack spoofing
│   ├── cipher/                             # Subsistema criptográfico y protocolo de canal seguro
│   │   ├── mod.rs                          # Exportación de tipos y submódulos criptográficos
│   │   ├── keys.rs                         # Identidades asimétricas X25519 y derivación de secretos
│   │   ├── cipher_data.rs                  # Motor de cifrado y descifrado autenticado ChaCha20-Poly1305
│   │   ├── handshake.rs                    # Protocolo de handshake con anonimización de clave pública
│   │   └── communication.rs                # Contenedor de paquetes de datos cifrados de sesión
│   ├── nt/                                 # Subsistema nativo de Windows NT (Kernel & NTDLL)
│   │   ├── mod.rs                          # Declaración de submódulos del kernel
│   │   ├── types.rs                        # Tipos base, máscaras de acceso y constantes NTSTATUS
│   │   ├── process/                        # Operaciones sobre procesos nativos
│   │   │   ├── mod.rs
│   │   │   ├── open_process.rs             # NtOpenProcess con CLIENT_ID y OBJECT_ATTRIBUTES
│   │   │   └── query_information_process.rs # NtQueryInformationProcess y enumeración de handles
│   │   ├── kernel_objects/                 # Gestión de objetos del núcleo
│   │   │   ├── mod.rs
│   │   │   ├── close.rs                    # Invocación indirecta de NtClose
│   │   │   ├── duplicate_object.rs         # Stub planificado para NtDuplicateObject
│   │   │   └── query_object.rs             # NtQueryObject y dimensionamiento dinámico de búfer
│   │   └── memory/                         # Gestión y análisis avanzado de memoria virtual
│   │       ├── mod.rs
│   │       ├── virtual_alloc.rs            # NtAllocateVirtualMemory (MEM_COMMIT, MEM_RESERVE)
│   │       ├── read_process_mem.rs         # NtReadVirtualMemory
│   │       ├── write_process_mem.rs        # NtWriteVirtualMemory
│   │       ├── protect_virtual_mem.rs      # NtProtectVirtualMemory y ajuste de límites por página
│   │       ├── query_virtual_mem.rs        # NtQueryVirtualMemory y mapeador visual del espacio virtual
│   │       └── pattern_scan_mem.rs         # Escaneo de firmas, límites .pdata y aleatoriedad OsRng
│   ├── structures/                         # Parsing manual de estructuras binarias e internas
│   │   ├── mod.rs
│   │   ├── pe/                             # Parsing manual de ejecutables portables (PE / PE32+)
│   │   │   ├── mod.rs
│   │   │   ├── constants.rs                # Firmas, números mágicos y offsets fijos PE
│   │   │   ├── headers.rs                  # Parsing de cabeceras DOS y NT (PeHeaderInfo)
│   │   │   ├── optional_header.rs          # ImageOptionalHeader64 y verificación de alineación
│   │   │   ├── export.rs                   # ExportTable, resolución de ordinales y Forwarded Exports
│   │   │   └── helpers.rs                  # Lectura de cadenas C terminadas en nulo (read_cstr)
│   │   └── peb/                            # Introspección del TEB, PEB y cargador dinámico (LDR)
│   │       ├── mod.rs
│   │       ├── peb.rs                      # Peb, lectura de GS:[0x60]/FS:[0x30] y detección de SO
│   │       ├── ldr.rs                      # Estructura _PEB_LDR_DATA (x64 y x86)
│   │       ├── ldr_entry.rs                # Evolución de _LDR_DATA_TABLE_ENTRY (Vista a Windows 11)
│   │       ├── list_entry.rs               # _LIST_ENTRY, containing_record e iterador ListIter
│   │       └── offsets/                    # Tablas de consulta exhaustivas de desplazamientos
│   │           ├── mod.rs
│   │           ├── peb_x64.rs              # Offsets de PEB para Vista, Win7, Win8, Win10 y Win11
│   │           └── peb_x86.rs              # Offsets de PEB para XP, Vista, Win7, Win8 y Win10
│   └── techniques/                         # Técnicas de evasión de defensas y descubrimiento
│       ├── mod.rs
│       ├── discovery/                      # Introspección y reconocimiento de procesos
│       │   ├── mod.rs
│       │   └── process.rs                  # Enumeración con NtQuerySystemInformation y tabla ASCII
│       └── evasion/                        # Mecanismos de evasión y ejecución oculta
│           ├── mod.rs
│           ├── api_hashing.rs              # Algoritmo FNV-1a modificado con ROR-7 y máscara XOR
│           ├── dinamic_api_resolution.rs   # Resolución de DLLs en PEB y funciones en EAT por hash
│           ├── syscall_opcodes.rs          # Catálogo de SSNs de referencia para Windows 10 x64
│           ├── execution/                  # Motores de ejecución y despacho de syscalls
│           │   ├── mod.rs
│           │   ├── dinamic_ssn.rs          # Extracción dinámica de SSN y detección de ganchos EDR
│           │   ├── direct_syscall.rs       # Syscalls directas en ensamblador inline (x64 y x86)
│           │   ├── dynamic_call.rs         # Envoltorios de llamada stdcall y cdecl por hash o nombre
│           │   ├── indirect_syscall.rs     # Indirect syscalls combinadas con Call Stack Spoofing
│           │   └── normal_call.rs          # Invocación tipada por aridad de punteros cdecl y stdcall
│           ├── memory/                     # Manipulación sigilosa de memoria
│           │   ├── mod.rs
│           │   └── write_process_mem_rw_rx.rs # Inyección en proceso mediante ciclo RW -> RX
│           └── stack_spoofing/             # Motor de falsificación sintética de pila
│               ├── mod.rs
│               ├── call_stack_spoofing.rs  # Construcción del marco falso y localización de gadgets
│               └── unwind_info.rs          # Parser de .pdata y decodificador de opcodes UNWIND_INFO
```

---

## Estructuras de Bajo Nivel (`src/structures/`)

### Parsing Manual del Formato PE (`src/structures/pe/`)

El análisis de ejecutables se realiza enteramente sobre la memoria del módulo cargado mediante operaciones aritméticas de punteros:

1. **Cabeceras DOS y NT (`headers.rs`):**
   - Se lee el desplazamiento de la cabecera NT en `base + 0x3C` (`e_lfanew`).
   - Se valida la firma `IMAGE_NT_SIGNATURE` (`0x4550`, correspondiente a `"PE\0\0"`).
   - Se ubica la cabecera opcional calculando `nt_headers_ptr + NT_SIGNATURE_SIZE (4) + FILE_HEADER_SIZE (20)`.
   - Se lee el número mágico: `PE32_MAGIC` (`0x010B`) o `PE32_PLUS_MAGIC` (`0x020B`).
2. **Cabecera Opcional y Verificación de Alineación (`optional_header.rs`):**
   - Mapea `ImageOptionalHeader64` con sus 16 entradas de `ImageDataDirectory`.
   - **Verificación Estricta de Alineación:** Antes de transformar la dirección en una referencia de Rust, se comprueba:
     ```rust
     if optional_header_base_addr % std::mem::align_of::<ImageOptionalHeader64>() != 0 {
         return Err("La dirección no está alineada");
     }
     ```
3. **Tabla de Exportaciones y Forwarded Exports (`export.rs`):**
   - Localiza `IMAGE_EXPORT_DIRECTORY` a partir del Data Directory 0 (`export_directory_offset`: `0x70` en PE32+, `0x60` en PE32).
   - Lee las tres tablas fundamentales: `AddressOfFunctions`, `AddressOfNames` y `AddressOfNameOrdinals`.
   - **Detección de Exportaciones Reenviadas (Forwarded Exports):** Si la RVA de una función se encuentra dentro del rango físico del directorio de exportación `[exp_rva, exp_rva + exp_size)`, la dirección no apunta a código ejecutable, sino a una cadena ASCII que referencia una función en otra DLL (por ejemplo, `NTDLL.RtlAllocateHeap`). El parser detecta esta condición, asigna un puntero virtual nulo (`va = null`) y almacena la referencia con el prefijo `[fwd] <dll>.<func>`:
     ```rust
     let export_range = exp_rva..exp_rva + exp_size;
     if export_range.contains(&(rva as usize)) {
         let fwd = read_cstr(base.add(rva as usize));
         entries.push(ExportEntry {
             ordinal: ordinal_base + i as u32,
             rva,
             va: core::ptr::null(),
             name: name_map[i].clone().or(Some(format!("[fwd] {fwd}"))),
         });
         continue;
     }
     ```

### Introspección del Runtime TEB / PEB / LDR (`src/structures/peb/`)

#### Obtención del PEB sin APIs del Sistema
El Thread Environment Block (TEB) almacena el puntero al Process Environment Block (PEB). Se extrae en tiempo de compilación mediante instrucciones de ensamblador en línea:
- **Arquitectura x86_64:** Registro de segmento `GS` en el desplazamiento `0x60`:
  ```rust
  #[cfg(target_arch = "x86_64")]
  unsafe {
      asm!("mov {0}, gs:[0x60]", out(reg) pebdir, options(nomem, nostack));
  }
  ```
- **Arquitectura x86:** Registro de segmento `FS` en el desplazamiento `0x30`:
  ```rust
  #[cfg(target_arch = "x86")]
  unsafe {
      asm!("mov {0}, fs:[0x30]", out(reg) pebdir, options(nomem, nostack));
  }
  ```

#### Detección Dinámica de la Versión del Sistema Operativo
Debido a que la disposición interna de los campos del PEB varía entre versiones de Windows, se implementa un mecanismo de arranque en dos fases (*bootstrapping*):
1. Los campos `OSMajorVersion` y `OSBuildNumber` se mantienen en offsets constantes desde Windows Vista tanto en x64 (`0x118` y `0x120`) como en x86 (`0x0A4` y `0x0AC`).
2. Se leen dichos campos para clasificar la versión del sistema operativo:
   - `build >= 22000` $\rightarrow$ Windows 11
   - `major == 10` $\rightarrow$ Windows 10
   - `major == 6 && build >= 9200` $\rightarrow$ Windows 8
   - `major == 6 && build >= 7600` $\rightarrow$ Windows 7
   - En cualquier otro caso $\rightarrow$ Windows Vista
3. Se carga dinámicamente la tabla `PebOffsets` con las posiciones de memoria exactas para la versión en ejecución.

#### Comparativa de Offsets del PEB en x64 (`peb_x64.rs`)

| Campo | Vista (0x368) | Win 7 (0x380) | Win 8 (0x388) | Win 10 22H2 (0x7C8) | Win 11 25H2 (0x7D0) |
|---|---|---|---|---|---|
| `BeingDebugged` | `0x002` | `0x002` | `0x002` | `0x002` | `0x002` |
| `ImageBaseAddress` | `0x010` | `0x010` | `0x010` | `0x010` | `0x010` |
| `Ldr` (`_PEB_LDR_DATA*`) | `0x018` | `0x018` | `0x018` | `0x018` | `0x018` |
| `ProcessParameters` | `0x020` | `0x020` | `0x020` | `0x020` | `0x020` |
| `ProcessHeap` | `0x030` | `0x030` | `0x030` | `0x030` | `0x030` |
| `FastPebLock` | `0x038` | `0x038` | `0x038` | `0x038` | `0x038` |
| `NtGlobalFlag` | `0x0BC` | `0x0BC` | `0x0BC` | `0x0BC` | `0x0BC` |
| `OSMajorVersion` | `0x118` | `0x118` | `0x118` | `0x118` | `0x118` |
| `OSBuildNumber` | `0x120` | `0x120` | `0x120` | `0x120` | `0x120` |

#### Estructuras del Cargador (`_PEB_LDR_DATA` y `_LDR_DATA_TABLE_ENTRY`)
- **`_PEB_LDR_DATA`:** Posee un tamaño total de `0x58` bytes en x64 y `0x30` bytes en x86. Contiene las cabeceras de las tres listas doblemente enlazadas del cargador: `InLoadOrderModuleList`, `InMemoryOrderModuleList` e `InInitializationOrderModuleList`.
- **Evolución de `_LDR_DATA_TABLE_ENTRY`:** La estructura de cada módulo cargado ha crecido a lo largo de las versiones de Windows:
  - Windows Vista: `0xC8` bytes.
  - Windows 7: `0xE0` bytes (incorpora `OriginalBase` y `LoadTime`).
  - Windows 8: `0x110` bytes (reemplazo de listas por grafos dirigidos acíclicos y nodos balanceados).
  - Windows 10 22H2: `0x120` bytes (incorpora `DependentLoadFlags` y `SigningLevel`).
  - Windows 11 24H2+: `0x138` bytes (añade `CheckSum`, `ActivePatchImageBase` y `HotPatchState`).

#### Navegación Circular con `_LIST_ENTRY` y Trait `Iterator`
Las listas enlazadas del núcleo de Windows son circulares. Para evitar bucles infinitos y desreferenciar los registros de forma idiomática:
1. Se implementa el cálculo de estructura contenedora (equivalente a la macro C `CONTAINING_RECORD`):
   ```rust
   pub unsafe fn containing_record(&self, field_offset: usize) -> *const u8 {
       unsafe { self.ptr.sub(field_offset) }
   }
   ```
2. Se implementa el iterador `ListIter` sobre `_LIST_ENTRY`, el cual detiene la iteración cuando el puntero actual regresa a la cabeza (`head`) o se vuelve nulo, permitiendo iterar módulos de forma segura en Rust:
   ```rust
   for node in head.iter() {
       let entry_ptr = ListEntry::new(node).containing_record(ldr_off::IN_LOAD_ORDER_LINKS);
       let entry = LdrDataTableEntry::new(entry_ptr);
       // Inspección segura de módulos...
   }
   ```

---

## Subsistema Nativo NT (`src/nt/`)

El módulo `src/nt/` provee envolturas sobre las llamadas al sistema del núcleo sin intermediarios.

### Tipos del Kernel NT (`src/nt/types.rs`)
Define los tipos primitivos del kernel: `HANDLE`, `SIZE_T`, `ULONG`, `LONG`, `ACCESS_MASK`, `LARGE_INTEGER`, `GENERIC_MAPPING` y la constante de error `STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820` (equivalente con signo a `0xC0000004`).

### Gestión de Procesos (`src/nt/process/`)

#### `open_process.rs`
- **Hash de API:** `0xaddc1c2e` (`NtOpenProcess`).
- **Máscara de Acceso (`DESIRED_ACCESS`):** Define `PROCESS_ALL_ACCESS` (`0x0410`), `PROCESS_VM_READ` (`0x0010`), `PROCESS_VM_WRITE` (`0x0020`), `PROCESS_VM_OPERATION` (`0x0008`) y `PROCESS_QUERY_INFORMATION` (`0x0400`), implementando el trait `BitOr` para su combinación natural mediante el operador `|`.
- **Estructuras Requeridas:** Configura `CLIENT_ID` (asignando el PID en `unique_process`) y `OBJECT_ATTRIBUTES` (fijando `length` en el tamaño de la estructura: 48 bytes en x64, 24 bytes en x86).
- **Despacho:** Resuelve dinámicamente el SSN de `NtOpenProcess` y ejecuta la syscall indirecta a través de `indirect_syscall_6`.

#### `query_information_process.rs`
- **Hash de API:** `0x6fa0c1f4` (`NtQueryInformationProcess`).
- **Enumeración de Descriptores (Handles):** Consulta la clase de información `ProcessHandleInformation` (`51`).
- **Bucle Dinámico de Reasignación:** Dado que la cantidad de handles de un proceso varía constantemente, implementa hasta 10 reintentos ante respuestas `STATUS_INFO_LENGTH_MISMATCH` (`0xC0000004`). Si el kernel devuelve la longitud requerida, añade un margen de seguridad (*slack*) de `16 * size_of::<PROCESS_HANDLE_TABLE_ENTRY_INFO>()`; si devuelve 0, duplica el tamaño anterior del búfer.
- **Visualización:** `print_all_handles_info(handle)` deserializa la estructura `PROCESS_HANDLE_SNAPSHOT_INFORMATION` y muestra en consola el valor del descriptor, los permisos concedidos (`GrantedAccess`) y el índice del tipo de objeto.

### Gestión de Objetos del Kernel (`src/nt/kernel_objects/`)

#### `close.rs`
- **Hash de API:** `0x1c0fcdc4` (`NtClose`).
- Invoca la syscall indirecta para liberar descriptores del kernel verificando el retorno `STATUS_SUCCESS` (`0`).

#### `query_object.rs`
- **Hash de API:** `0xfc2a599c` (`NtQueryObject`).
- **Clases de Información:** Modela `OBJECT_INFORMATION_CLASS` (`ObjectBasicInformation = 0`, `ObjectNameInformation = 1`, `ObjectTypeInformation = 2`, `ObjectTypesInformation = 3`, `ObjectHandleFlagInformation = 4`, etc.).
- **Sondeo y Dimensionamiento Dinámico:**
  - `query_object_find_struct_size`: Realiza un sondeo previo con búfer nulo y tamaño 0 capturando los estados `STATUS_INFO_LENGTH_MISMATCH` (`0xC0000004`) o `STATUS_BUFFER_TOO_SMALL` (`0xC0000023`) para conocer el tamaño requerido por el sistema.
  - `query_object_size_solved`: Gestiona un bucle de hasta 20 iteraciones que reasigna búferes con holgura hasta completar con éxito la consulta de tipos de objetos (`OBJECT_TYPES_INFORMATION`).

#### `duplicate_object.rs`
- **Estado de Auditoría:** Contiene actualmente la declaración comentada `// Implementación futura de NtDuplicateObject`. Se encuentra catalogada como función planificada para futuras iteraciones del proyecto.

### Gestión Avanzada de Memoria Virtual (`src/nt/memory/`)

#### `virtual_alloc.rs`
- **Hash de API:** `0x2759addf` (`NtAllocateVirtualMemory`).
- Enums `AllocationType` (`MEM_COMMIT = 0x1000`, `MEM_RESERVE = 0x2000`, `MEM_RESET`, `MEM_TOP_DOWN`) y `PageProtection` (`PAGE_READONLY`, `PAGE_READWRITE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`).
- Maneja parámetros de entrada/salida para la dirección base y el tamaño de la asignación.

#### `read_process_mem.rs` y `write_process_mem.rs`
- **Hashes de API:** `0x7a58c6ca` (`NtReadVirtualMemory`) y `0x7f603ee9` (`NtWriteVirtualMemory`).
- Lectura y escritura atómica en procesos locales o remotos recogiendo los bytes efectivamente transferidos.

#### `protect_virtual_mem.rs`
- **Hash de API:** `0x96e11bf8` (`NtProtectVirtualMemory`).
- Modifica permisos de páginas gestionando el redondeo obligatorio que realiza el kernel NT hacia los límites de página inferior y superior, devolviendo la tupla `(boundary_address, boundary_size, old_protect)`.

#### `query_virtual_mem.rs`
- **Hash de API:** `0xbe409009` (`NtQueryVirtualMemory`).
- Consulta metadatos mediante la estructura `MEMORY_BASIC_INFORMATION` (que incorpora `PartitionId: u16` bajo la arquitectura x64).
- **Mapeador Visual de Memoria (`escanear_memoria_proceso`):** Recorre exhaustivamente el espacio virtual de direcciones en modo usuario (desde `0x00000` hasta `0x7FFFFFFFFFFF`). Para cada bloque en estado `MEM_COMMIT`, traduce los flags de protección a etiquetas compactas (`RW`, `RWX`, `RX`, `RO`, `X`) e imprime una tabla estructurada Unicode que detalla la dirección base, el tamaño de la región y sus atributos de ejecución.

#### `pattern_scan_mem.rs`: Escaneo de Patrones y Delimitación mediante `.pdata`
- `mem_remote_pattern_find`: Lee bloques de memoria de un proceso remoto y busca secuencias de bytes mediante ventanas deslizantes (`buffer.windows()`).
- `mem_local_pattern_find`: Busca simultáneamente múltiples patrones en rangos de memoria locales sin requerir alineación.
- `get_pdata_func_info`: Conecta con el directorio de excepciones `.pdata` para delimitar el inicio (`begin_address`) y el final (`end_address`) de una función legítima.
- `pdata_pattern_find_starting_at_rand_func`: Inspecciona el conjunto total de funciones en `.pdata`, selecciona un índice aleatorio inicial utilizando `rand_core::OsRng` y recorre circularmente las funciones de una DLL. Esta técnica permite ubicar gadgets o secuencias de instrucciones evitando patrones fijos de búsqueda secuencial que alertarían a motores de telemetría.
- `find_pattern_in_specific_func`: Acota la búsqueda del patrón de bytes a los límites exactos de una función específica indicada por su RVA (utilizada para ubicar el gadget `syscall; ret`).

---

## Técnicas de Evasión y Descubrimiento (`src/techniques/`)

### API Hashing y Ofuscación Estática (`src/techniques/evasion/api_hashing.rs`)

Para evitar almacenar cadenas de texto legibles que puedan ser analizadas estáticamente por utilidades como `strings` o reglas YARA, se implementa una variación robusta del algoritmo FNV-1a:

```rust
#[inline]
pub fn unique_hash(name: &str) -> u32 {
    let bytes = name.as_bytes();
    let mut hash: u32 = 0x811C9DC5; // FNV offset basis
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(16777619); // FNV prime
        hash = (hash >> 7) | (hash << (32 - 7)); // Rotación circular a la derecha (ROR 7)
        i += 1;
    }
    hash ^ 0x7F3A9C12 // Máscara XOR final
}
```

#### Constantes y Hashes Precalculados

| Cadena Objetivo | Hash de 32 Bits Resultante |
|---|---|
| `"ntdll.dll"` (minúsculas) | `0x68861c6f` |
| `"kernel32.dll"` (minúsculas) | `0xd32210ae` |
| `"NtOpenProcess"` | `0xaddc1c2e` |
| `"NtQueryInformationProcess"` | `0x6fa0c1f4` |
| `"NtQueryObject"` | `0xfc2a599c` |
| `"NtAllocateVirtualMemory"` | `0x2759addf` |
| `"NtReadVirtualMemory"` | `0x7a58c6ca` |
| `"NtWriteVirtualMemory"` | `0x7f603ee9` |
| `"NtProtectVirtualMemory"` | `0x96e11bf8` |
| `"NtQueryVirtualMemory"` | `0xbe409009` |
| `"NtClose"` | `0x1c0fcdc4` |
| `"NtQuerySystemInformation"` | `0xc3d78064` |
| `"RtlUserThreadStart"` | `0xec14be5f` |
| `"BaseThreadInitThunk"` | `0x9941b145` |
| `"strcpy"` | `0x097c4468` |

### Resolución Dinámica de APIs (`src/techniques/evasion/dinamic_api_resolution.rs`)
Permite ubicar módulos y funciones en memoria sin interactuar con la IAT:
- `get_ntdll_base()` y `get_kernel32_base()`: Recorren `InLoadOrderModuleList` del PEB y comparan los hashes de los nombres de módulos en minúsculas.
- `get_dll_base_by_hash(hash: u32)`: Localiza cualquier DLL cargada a partir de su hash FNV-1a/ROR.
- `get_export_by_name` y `get_export_by_name_hash`: Parsean la tabla de exportaciones del módulo objetivo para obtener la dirección virtual de la función deseada.

### Extracción Dinámica de SSN: Hell's Gate y Halo's Gate (`src/techniques/evasion/execution/dinamic_ssn.rs`)

El hardcodeo de los System Service Numbers (SSN) es inestable debido a que Microsoft los altera con frecuencia entre parches y compilaciones del kernel. El módulo `dinamic_ssn.rs` extrae el SSN en tiempo de ejecución analizando el código máquina del prólogo de la función en `ntdll.dll`:

1. **Patrón de Stub en Windows x64:** El inicio estándar de una función de llamada al sistema en NTDLL presenta los siguientes bytes:
   ```text
   4C 8B D1         mov r10, rcx
   B8 XX XX 00 00   mov eax, <SSN>
   ```
2. **Inspección de Opcodes:** Se localiza el byte `0xB8` y se verifica que los 3 bytes inmediatamente anteriores correspondan a `[0x4C, 0x8B, 0xD1]`. El valor de 32 bits situado inmediatamente después de `0xB8` se extrae como el SSN legítimo.
3. **Detección de Ganchos (Hooks) de EDR:** Si una solución de seguridad ha colocado un gancho (hook) en el prólogo de la función:
   - Presencia de 3 bytes consecutivos `0xCC` (`INT3` / breakpoint de depuración).
   - Presencia de 2 bytes consecutivos `0x90` (`NOP` sled previo a un salto `JMP`).
   - La función aborta el intento notificando la detección del gancho, permitiendo en implementaciones Halo's Gate escanear stubs vecinos arriba o abajo para deducir el SSN por adyacencia.

> [!NOTE]
> **Reflexión del autor sobre WoW64 y la decisión de 64 bits:**
> En el código fuente dejé una anotación clara sobre el alcance arquitectónico:
> *"la indirect syscall solo las implemento para x64 dado que para x86 en un entorno wow64 habria que hacer Heaven's Gate y pasar por las syscalls de nt64 y eso es un lio"*.
> En sistemas de 64 bits modernos, un proceso de 32 bits bajo el emulador WoW64 no ejecuta syscalls nativas de 32 bits directas al kernel; en su lugar, atraviesa una compuerta (*Heaven's Gate*) cambiando el descriptor de segmento de código a `0x33` para saltar a un `ntdll.dll` de 64 bits. Por este motivo, concentré toda la infraestructura de indirect syscalls y spoofing en x86_64, donde la telemetría de los EDRs inspecciona rigurosamente los marcos de 64 bits.

### Despacho de Syscalls Directas (`src/techniques/evasion/execution/direct_syscall.rs`)
Implementa `direct_syscall_6` mediante ensamblador en línea para x64 (configurando el shadow space de 32 bytes, los argumentos quinto y sexto en la pila y la instrucción `syscall`) y para x86 (empujando argumentos y ejecutando la instrucción `sysenter`).

---

## Evasión Avanzada: Indirect Syscalls y Call Stack Spoofing

Cuando una aplicación ejecuta directamente la instrucción `syscall` desde su propia sección de memoria privada (`.text`), los controladores del kernel (mediante eventos de telemetría como Microsoft-Windows-Threat-Intelligence / ETW-Ti) y los mecanismos de inspección de hilos registran que la llamada se originó fuera del espacio de memoria de `ntdll.dll`. Esta anomalía provoca alertas inmediatas en soluciones EDR.

Para neutralizar este vector, `zada-xor` implementa **Indirect Syscalls** combinadas con **Call Stack Spoofing sintético** guiado por el directorio de excepciones `.pdata`.

### Salto Indirecto a `ntdll.dll`
En lugar de emitir la instrucción `syscall` en memoria propia:
1. Se localiza una secuencia legítima `syscall; ret` (`0x0F, 0x05, 0xC3`) dentro de la propia función en `ntdll.dll` mediante `find_pattern_in_specific_func`.
2. Se realiza un salto incondicional `jmp` hacia esa dirección en NTDLL. De esta forma, el registro `RIP` del procesador durante la transición a Ring 0 pertenece legítimamente al espacio de direcciones firmado de Microsoft NTDLL.

### Falsificación de la Pila de Llamadas (Call Stack Spoofing)

El motor de falsificación engaña a los algoritmos de desenrollado de pila (*stack walking*, como `RtlVirtualUnwind`) simulando un hilo que nació legítimamente en los puntos de entrada del sistema operativo.

#### 1. Decodificación de `.pdata` y `UNWIND_INFO` (`unwind_info.rs`)
En Windows x64, toda función que reserva espacio en la pila o gestiona excepciones debe registrar una entrada de 12 bytes `IMAGE_RUNTIME_FUNCTION_ENTRY` en la sección `.pdata`. El motor de `unwind_info.rs` decodifica la cabecera `ImageUnwindInfo` y sus slots de 2 bytes `UNWIND_CODE`:
- **Opcode 0 (`UWOP_PUSH_NONVOL`):** Suma 8 bytes de pila (`push <reg>`).
- **Opcode 1 (`UWOP_ALLOC_LARGE`):** Suma `slot * 8` bytes (si `info == 0`) o un valor de 32 bits (si `info == 1`).
- **Opcode 2 (`UWOP_ALLOC_SMALL`):** Suma `(info * 8) + 8` bytes (entre 8 y 128 bytes).
- **Opcodes 4 y 8 (`UWOP_SAVE_NONVOL`):** Guarda registros mediante `mov` sin alterar el tamaño de pila.
- **Opcode 10 (`UWOP_PUSH_MACHFRAME`):** Suma 40 o 48 bytes (marcos de interrupción del sistema).
- **Extensiones Encadenadas (`UNW_FLAG_CHAININFO`):** Sigue recursivamente punteros a estructuras `UNWIND_INFO` adicionales.

> [!NOTE]
> **Reflexión del autor sobre el motor de Unwinding dinámico:**
> El mayor reto técnico al diseñar el módulo de evasión fue evitar los tamaños de pila fijos (*hardcoded offsets*). Muchas pruebas de concepto públicas asumen que `BaseThreadInitThunk` siempre reserva un número fijo de bytes. Sin embargo, entre diferentes compilaciones de Windows 10 y Windows 11, las actualizaciones acumulativas modifican las funciones y cambian los tamaños del marco. Desarrollar un analizador completo de `.pdata` que decodifica los opcodes `UNWIND_CODE` en memoria garantiza que el tamaño de la pila sintética coincida matemáticamente con lo que espera el desenrollador del sistema operativo, evitando desalineaciones fatales al retornar.

#### 2. Localización de Gadgets en NTDLL
Mediante `prepare_gadget_spoof_data`, se buscan dos gadgets en memoria legítima de NTDLL:
- **Gadget 1:** `ADD RSP, 0x38; RET` (secuencia `[0x48, 0x83, 0xC4, 0x38, 0xC3]`), validando en `.pdata` que la función que lo alberga tenga un marco de exactamente 56 bytes (`0x38`).
- **Gadget 2:** `CALL <AnchorReg>` (donde el registro ancla puede ser `RDI`, `RSI`, `R15` o `R12`), permitiendo retomar el control en nuestro código tras la llamada sin ensuciar la pila con un retorno espurio.

#### 3. Estructura Sintética de la Pila en Ejecución

```text
================================================================================
[RSP + pos4] (Base)          -> Dirección de Gadget 1: ADD RSP, 0x38; RET
                                (La Syscall en NTDLL ejecuta RET y aterriza aquí)
[RSP + 0x08]                 -> Shadow Space 1 (Basura / RCX)
[RSP + 0x10]                 -> Shadow Space 2 (Basura / RDX)
[RSP + 0x18]                 -> Shadow Space 3 (Basura / R8)
[RSP + 0x20]                 -> Shadow Space 4 (Basura / R9)
[RSP + 0x28]                 -> Argumento 5 de la Syscall
[RSP + 0x30]                 -> Argumento 6 de la Syscall
================================================================================
...                          -> El Gadget 1 ejecuta "ADD RSP, 0x38", limpiando los
                                56 bytes anteriores, y ejecuta "RET".
================================================================================
[RSP + pos3] (offset4 + 8)   -> Dirección de Gadget 2: CALL <AnchorReg>
                                (Aterriza aquí. El CALL devuelve la ejecución a Rust)
================================================================================
...                          -> Espacio de frame asignado al Gadget 2 (según .pdata)
================================================================================
[RSP + pos2]                 -> Dirección legítima: BaseThreadInitThunk + 0x14
================================================================================
...                          -> Espacio de frame de BaseThreadInitThunk (según .pdata)
================================================================================
[RSP + pos1]                 -> Dirección legítima: RtlUserThreadStart + 0x21
================================================================================
...                          -> Espacio de frame de RtlUserThreadStart (según .pdata)
================================================================================
[RSP + null_ret_offset]      -> 0x0000000000000000 (NULL RETURN ADDRESS)
                                (El analizador de pila lee 0x0 y concluye que el hilo
                                 se originó limpiamente en el inicio del proceso).
================================================================================
```

*Nota sobre las direcciones simuladas:* Se añade intencionalmente un desplazamiento de `+0x21` a `RtlUserThreadStart` y `+0x14` a `BaseThreadInitThunk`. Si las direcciones de retorno apuntasen al byte 0 de las funciones, los analizadores de seguridad detectarían de inmediato la falsificación, dado que una llamada `CALL` real jamás retorna al inicio de una función anfitriona.

---

## Técnicas Complementarias de Invocación y Memoria

### Inyección de Memoria Sigilosa RW $\rightarrow$ RX (`write_process_mem_rw_rx.rs`)
La asignación directa de regiones con permisos de lectura, escritura y ejecución simultáneos (`PAGE_EXECUTE_READWRITE` / RWX) es una de las principales heurísticas de detección en monitores de memoria.
El módulo `write_process_mem_rw_rx` implementa un ciclo de protección en tres fases:
1. **Fase 1 (Reserva RW):** Asigna la región con permisos `PAGE_READWRITE` mediante `nt_allocate_virtual_memory`.
2. **Fase 2 (Escritura):** Transfiere la carga útil mediante `nt_write_virtual_memory`.
3. **Fase 3 (Transición a RX):** Modifica la protección a `PAGE_EXECUTE_READ` mediante `nt_protect_virtual_memory`.
La región resultante nunca existió con permisos simultáneos de escritura y ejecución.

### Envoltorios de Invocación Dinámica (`dynamic_call.rs` y `normal_call.rs`)
Permiten invocar funciones exportadas de `ntdll.dll` mediante las convenciones `cdecl` y `stdcall` desempaquetando hasta 10 argumentos:
- **Arquitectura x86:** En `stdcall`, la función llamada limpia la pila (`ret N`), mientras que en `cdecl`, es el llamador quien ajusta `ESP`. Para evitar la corrupción de la pila, `normal_call.rs` implementa un bifurcador exhaustivo por aridad de argumentos (`match args.len()`) que transmuta el puntero a firmas exactas con entre 0 y 9 parámetros.
- **Arquitectura x64:** Dado que la ABI de Microsoft unifica las convenciones utilizando los registros `RCX`, `RDX`, `R8`, `R9` y la pila para los parámetros restantes, las funciones transmutan directamente al puntero genérico de 10 argumentos.

### Descubrimiento e Introspección de Procesos (`src/techniques/discovery/process.rs`)
Realiza la enumeración del sistema operativo sin emplear APIs de alto nivel (`CreateToolhelp32Snapshot` o `EnumProcesses`):
1. Resuelve dinámicamente el SSN de `NtQuerySystemInformation` (hash `0xc3d78064`).
2. Invoca la syscall indirecta consultando la clase `SystemProcessInformation` (`5`).
3. Comprueba el código `STATUS_INFO_LENGTH_MISMATCH` (`0xC0000004`), reserva memoria dinámica en el heap nativo (`std::alloc::alloc`) añadiendo un margen de holgura de 8 KB (`+ 0x2000`) para absorber procesos creados concurrentemente, y realiza una segunda llamada para rellenar los datos.
4. Parsea las estructuras `SystemProcessInformation` leyendo los identificadores PID, PPID, número de hilos, descriptores, memoria privada y nombres de imagen (`image_name.to_string()`).
5. `get_process_table()` formatea la información en una tabla estructurada en consola con caracteres gráficos Unicode.

---

## Subsistema Criptográfico y Canal Seguro (`src/cipher/`)

El módulo `src/cipher/` proporciona un canal de comunicaciones cifrado y autenticado punto a punto entre el agente y el servidor C2.

```text
+---------------------------------------------------------------------------------------+
| CLIENTE                                                          SERVIDOR             |
|                                                                                       |
| 1. Genera Secreto Efímero (sk_e)                                                      |
|    Deriva Clave Pública Efímera (pk_e)                                                |
| 2. Computa SS = ECDH(sk_e, pk_server_static)                                          |
| 3. Clave Simétrica Temporal K_temp = SS                                               |
| 4. Cifra su Clave Pública Estática Real:                                              |
|    Ciphered_Client_Pub = K_temp.cipher(pk_client_static)                              |
| 5. Transmite Paquete Handshake (92 Bytes en total):                                   |
|    [ pk_e (32B) ] + [ Ciphered_Client_Pub (60B: 12B nonce + 32B pub + 16B tag) ]      |
|    =======================================================>                           |
|                                                              6. Recibe pk_e           |
|                                                              7. Computa SS =          |
|                                                                 ECDH(sk_server, pk_e) |
|                                                              8. Deriva K_temp = SS    |
|                                                              9. Descifra y valida:    |
|                                                                 pk_client_static =    |
|                                                                 K_temp.decipher(...)  |
|                                                              10. Sesión Establecida   |
+---------------------------------------------------------------------------------------+
```

### Gestión de Identidad Asimétrica (`keys.rs`)
- **`Identity`:** Representa la identidad a largo plazo. Genera una clave privada estática (`StaticSecret`) con `OsRng` y deriva su clave pública asociada (`PublicKey`) en Curve25519.
- **`SymetricKey`:** Deriva un secreto compartido de 32 bytes (`[u8; 32]`) mediante Diffie-Hellman en X25519 (`my_secret.diffie_hellman(their_public)`). Toma posesión (`move`) del secreto efímero para garantizar su destrucción inmediata en memoria.

### Cifrado Simétrico Autenticado AEAD ChaCha20-Poly1305 (`cipher_data.rs`)

> [!NOTE]
> **Reflexión del autor sobre la elección de ChaCha20-Poly1305:**
> En el código documenté expresamente:
> *"implemento cifrado y descifrado con chacha20 de payloads por salirme un poco del tipico xor"*.
> En la mayoría de investigaciones y muestras de malware, los canales de comunicación y la ofuscación de configuraciones recurren a esquemas basados en XOR estático o de clave rodante. Estos mecanismos carecen de integridad matemática y son trivialmente derrotados por análisis de frecuencia de bytes o ataques de texto plano conocido (*KPA*). La adopción de ChaCha20-Poly1305 garantiza un cifrador de flujo de alta velocidad sin aceleración por hardware obligatoria (a diferencia de AES-NI) y añade el tag MAC Poly1305 para garantizar la autenticidad e integridad del paquete.

#### Estructura del Sobre de Datos (Payload Envelope)

Cada mensaje cifrado se serializa con un encabezado fijo de 28 bytes de sobrecarga (*overhead*):

| Offset (Bytes) | Longitud | Campo | Descripción |
|---|---|---|---|
| `0x00 .. 0x0B` | 12 bytes | **Nonce** | Vector de inicialización aleatorio de 96 bits generado con `OsRng` |
| `0x0C .. (0x0C + N - 1)` | $N$ bytes | **Ciphertext** | Carga útil cifrada mediante el flujo ChaCha20 |
| `(0x0C + N) .. Final` | 16 bytes | **Poly1305 Tag** | Código de autenticación de mensaje de 128 bits |

Al descifrar, el motor valida que el búfer contenga al menos 12 bytes, separa el nonce y pasa el texto cifrado con su tag al autenticador. Si cualquier byte del paquete es modificado en tránsito, la verificación matemática falla inmediatamente y el mensaje se rechaza con error.

### Protocolo de Handshake con Anonimización de Clave (`handshake.rs`)

En un despliegue operativo, el cliente conoce la clave pública del servidor, pero si transmitiera su propia clave pública estática en texto claro para autenticarse, un analista de red o sensor NTA identificaría la huella del agente.
Para garantizar el anonimato:
1. El cliente genera una clave efímera única para el handshake.
2. Calcula un secreto compartido temporal contra la clave pública del servidor.
3. Cifra su clave pública real utilizando dicho secreto temporal.
4. Transmite el paquete `SecureClientHandshakePacket`:
   - 32 bytes de clave pública efímera en texto claro.
   - 60 bytes de clave pública estática cifrada (12B nonce + 32B clave pública + 16B tag Poly1305).
   - **Tamaño total transmitido:** **92 bytes**.
5. El servidor recibe la clave efímera, computa el mismo secreto compartido temporal y descifra la clave pública real del cliente, estableciendo el canal seguro.

---

## Binarios de Demostración y Validación (`src/bin/`)

El repositorio incluye dos programas ejecutables diseñados para validar experimentalmente todos los componentes implementados.

### 1. `src/bin/prueba.rs`: Suite Integral de 25 Pasos

Este binario ejecuta de forma secuencial una demostración de integración completa:

1. **Identificación:** Muestra el PID del proceso actual mediante `std::process::id()`.
2. **API Hashing:** Calcula el hash FNV-1a de `"NtQueryObject"` comprobando el resultado `0xfc2a599c`.
3. **Descubrimiento de Procesos:** Ejecuta `get_process_table()`, invocando `NtQuerySystemInformation` por syscall indirecta y visualizando la tabla de procesos.
4. **Interacción:** Solicita al operador ingresar un PID objetivo del sistema para las pruebas de manipulación de memoria.
5. **Apertura de Proceso:** Invoca `open_process` con permisos `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION` vía syscall indirecta de `NtOpenProcess` (hash `0xaddc1c2e`).
6. **Inspección de Objetos del Kernel:** Invoca `query_object_size_solved` con `OBJECT_INFORMATION_CLASS::ObjectTypesInformation`, gestionando el dimensionamiento dinámico de búfer.
7. **Enumeración de Descriptores:** Llama a `print_all_handles_info`, listando handles abiertos y sus permisos.
8. **Inyección de Memoria Sigilosa:** Ejecuta `write_process_mem_rw_rx`, reservando memoria en `PAGE_READWRITE`, escribiendo la cadena `"RustInternals123"` y cambiando la protección a `PAGE_EXECUTE_READ`.
9. **Parsing Manual PE:** Resuelve la base de `ntdll.dll` navegando el PEB y parsea manualmente las cabeceras PE con `PeHeaderInfo::parse_headers`.
10. **Generación de Claves:** Instancia `Identity` para cliente y servidor y genera el paquete de handshake.
11. **Demostración de Hashing:** Imprime hashes de funciones del sistema (`"RtlUserThreadStart"`, `"BaseThreadInitThunk"`, `"NtClose"`).
12. **Mapeo de Memoria Inicial:** Ejecuta `escanear_memoria_proceso` imprimiendo el mapa visual de regiones `MEM_COMMIT` y sus permisos.
13. **Verificación de Lectura/Escritura:** Lee la memoria inyectada con `nt_read_virtual_memory`, la sobrescribe con `"Terobolavariable"` mediante `nt_write_virtual_memory` y vuelve a leer para verificar el cambio.
14. **Modificación a RWX:** Modifica permisos de página a `ExecuteReadWrite` mediante `nt_protect_virtual_memory`.
15. **Mapeo de Memoria Actualizado:** Vuelve a ejecutar `escanear_memoria_proceso`, evidenciando la nueva región marcada como `RWX`.
16. **Cierre de Descriptor:** Cierra el handle mediante `nt_close` invocando la syscall indirecta de `NtClose` (hash `0x1c0fcdc4`).
17. **Finalización del Handshake:** El servidor procesa el paquete `SecureClientHandshakePacket`, descifra la clave del cliente y valida la igualdad matemática de las claves simétricas derivadas.
18. **Canal de Datos Cifrado:** Cifra y descifra un mensaje plano con `SecureDataPacket`.
19. **Prueba de Resistencia a Manipulación (Tampering):** Altera el primer byte del mensaje cifrado (`data_alterado[0] = 0`) y comprueba que Poly1305 detecta la manipulación y rechaza el descifrado.
20. **Inspección del PEB:** Instancia `Peb`, lee el selector `GS`/`FS`, detecta la versión del SO e imprime campos críticos (`ImageBaseAddress`, `BeingDebugged`, `NtGlobalFlag`, etc.).
21. **Navegación de LDR:** Itera `InLoadOrderModuleList` mediante `ListIter` imprimiendo DLLs cargadas, bases e imágenes.
22. **Parsing de Exportaciones de NTDLL:** Parsea la tabla de exportación de `ntdll.dll` y ubica `"strcpy"` por hash (`0x097c4468`).
23. **Llamada Dinámica Stdcall:** Congela el hilo durante 3 segundos con `dynamic_stdcall_by_name("NtDelayExecution", ...)`.
24. **Llamada Dinámica Cdecl:** Invoca `"strcpy"` en memoria mediante `dynamic_cdecl_by_name`.
25. **Comparativa de Syscalls:**
    - Ejecuta `direct_syscall_6` con SSN hardcodeado (`0x0034`) congelando el hilo.
    - Extrae el SSN dinámico de `NtDelayExecution` mediante `get_dinamic_ssn`.
    - Ejecuta `indirect_syscall_6` con SSN dinámico y Call Stack Spoofing falsificando la pila con marcos `.pdata` de NTDLL.

### 2. `src/bin/prueba_call_spoofing.rs`: PoC Especializada

Este binario proporciona una verificación aislada y limpia de la evasión de pila:
1. Define un retardo negativo de 60 segundos (`delay_interval = -(60 * 10_000_000)` en unidades de 100 nanosegundos).
2. Extrae dinámicamente el SSN de `NtDelayExecution` analizando el código máquina de `ntdll.dll`.
3. Ejecuta `indirect_syscall_6`: calcula marcos sintéticos de `RtlUserThreadStart` y `BaseThreadInitThunk`, ubica los gadgets ROP `ADD RSP, 0x38; RET` y `CALL <AnchorReg>`, inyecta la dirección nula `0x0`, agranda la pila y salta a la instrucción `syscall` dentro de `ntdll.dll`.
4. El hilo entra en estado de espera durante 60 segundos mientras cualquier inspección del stack registra una traza legítima.

---

## Compilación, Optimización y Entornos de Laboratorio

### Perfil de Optimización en `Cargo.toml`

La configuración del perfil de lanzamiento (`[profile.release]`) está diseñada para minimizar el tamaño del binario y dificultar el análisis forense:

```toml
[profile.release]
opt-level = "z"     # Optimización agresiva orientada a reducir el tamaño del código máquina
lto = true          # Link-Time Optimization entre todos los crates para eliminar código muerto
codegen-units = 1   # Generación de código unificada para permitir optimizaciones globales en LLVM
panic = "abort"     # Desactiva las tablas de desenrollado de pánicos, reduciendo el footprint binario
strip = true        # Elimina símbolos de depuración y metadatos del ejecutable PE final
```

### Compilación Cruzada (Cross-Compilation para Windows)

Desde entornos Linux, se compila utilizando el toolchain GNU de Windows:

#### Arquitectura de 64 bits (x86_64) — *Target Operativo Principal*
```bash
cargo build --target x86_64-pc-windows-gnu --bin prueba --release
cargo build --target x86_64-pc-windows-gnu --bin prueba_call_spoofing --release
```

#### Arquitectura de 32 bits (i686) — *Estado de Compatibilidad*
```bash
cargo build --target i686-pc-windows-gnu --bin prueba --release
```

> [!TIP]
> **Nota sobre la compatibilidad de compilación en 32 bits (`i686`):**
> Los módulos `src/structures/pe/` y `src/structures/peb/` contienen definiciones y offsets completos para 32 bits (x86). Sin embargo, el subsistema de despacho de llamadas al sistema (`dinamic_ssn.rs` e `indirect_syscall.rs`) está delimitado condicionalmente mediante `#[cfg(target_arch = "x86_64")]` debido a que las indirect syscalls con spoofing en Windows x86 requerirían implementar la compuerta *Heaven's Gate* en entornos WoW64. Por tanto, el objetivo plenamente funcional y soportado para la ejecución de pruebas y evasión es **`x86_64-pc-windows-gnu`**.

### Ejecución en Laboratorio con Wine

Para pruebas dinámicas en entornos Linux sin requerir una máquina virtual Windows dedicada, los binarios pueden ejecutarse mediante Wine utilizando prefijos limpios y aislados:

#### Ejecución en Entorno Wine de 64 bits
```bash
WINEPREFIX=~/.wine64 WINEARCH=win64 wine target/x86_64-pc-windows-gnu/release/prueba.exe
```

#### Ejecución de la PoC de Call Stack Spoofing en Wine 64 bits
```bash
WINEPREFIX=~/.wine64 WINEARCH=win64 wine target/x86_64-pc-windows-gnu/release/prueba_call_spoofing.exe
```

#### Ejecución en Entorno Wine de 32 bits
```bash
WINEPREFIX=~/.wine32 WINEARCH=win32 wine target/i686-pc-windows-gnu/release/prueba.exe
```

---

## Matriz Resumen de Archivos y Componentes

| Submódulo | Archivo | Funciones / Estructuras Clave | Responsabilidad Técnica |
|---|---|---|---|
| **Raíz** | `src/lib.rs` | Declaración de módulos públicos | Estructura modular del crate |
| **Utilidades** | `src/utils.rs` | `read_u8`, `read_u16`, `read_u32`, `read_ptr`, `UnicodeString` | Lectura de memoria sin alinear y conversión UTF-16 a UTF-8 |
| **NT Tipos** | `src/nt/types.rs` | `HANDLE`, `LARGE_INTEGER`, `STATUS_INFO_LENGTH_MISMATCH` | Definición de tipos primitivos del kernel NT |
| **NT Procesos** | `src/nt/process/open_process.rs` | `open_process`, `DESIRED_ACCESS`, `CLIENT_ID`, `OBJECT_ATTRIBUTES` | Apertura de procesos nativa vía `NtOpenProcess` (0xaddc1c2e) |
| **NT Procesos** | `src/nt/process/query_information_process.rs` | `query_information_process`, `print_all_handles_info` | Enumeración de handles vía `NtQueryInformationProcess` (0x6fa0c1f4) |
| **Kernel Objects** | `src/nt/kernel_objects/close.rs` | `nt_close` | Cierre de descriptores del kernel vía `NtClose` (0x1c0fcdc4) |
| **Kernel Objects** | `src/nt/kernel_objects/duplicate_object.rs` | Placeholder comentado | Stub planificado para `NtDuplicateObject` |
| **Kernel Objects** | `src/nt/kernel_objects/query_object.rs` | `query_object_find_struct_size`, `query_object_size_solved` | Consulta y dimensionamiento dinámico vía `NtQueryObject` (0xfc2a599c) |
| **NT Memoria** | `src/nt/memory/virtual_alloc.rs` | `nt_allocate_virtual_memory`, `AllocationType`, `PageProtection` | Asignación de memoria vía `NtAllocateVirtualMemory` (0x2759addf) |
| **NT Memoria** | `src/nt/memory/read_process_mem.rs` | `nt_read_virtual_memory` | Lectura de memoria remota vía `NtReadVirtualMemory` (0x7a58c6ca) |
| **NT Memoria** | `src/nt/memory/write_process_mem.rs` | `nt_write_virtual_memory` | Escritura de memoria remota vía `NtWriteVirtualMemory` (0x7f603ee9) |
| **NT Memoria** | `src/nt/memory/protect_virtual_mem.rs` | `nt_protect_virtual_memory`, `MemoryProtection` | Modificación de permisos de página vía `NtProtectVirtualMemory` (0x96e11bf8) |
| **NT Memoria** | `src/nt/memory/query_virtual_mem.rs` | `nt_query_virtual_memory`, `escanear_memoria_proceso` | Consulta de páginas (`MEMORY_BASIC_INFORMATION`) y mapa visual de memoria |
| **NT Memoria** | `src/nt/memory/pattern_scan_mem.rs` | `mem_remote_pattern_find`, `pdata_pattern_find_starting_at_rand_func` | Escaneo de secuencias de bytes, límites `.pdata` y búsqueda aleatoria con `OsRng` |
| **PE Parser** | `src/structures/pe/constants.rs` | `DOS_E_LFANEW`, `PE_SIGNATURE`, `PE32_PLUS_MAGIC` | Constantes y números mágicos del formato Portable Executable |
| **PE Parser** | `src/structures/pe/headers.rs` | `PeHeaderInfo::parse_headers` | Parsing manual de cabeceras DOS y NT |
| **PE Parser** | `src/structures/pe/optional_header.rs` | `ImageOptionalHeader64`, `ImageDataDirectory` | Análisis de la cabecera opcional y comprobación de alineación de memoria |
| **PE Parser** | `src/structures/pe/export.rs` | `ExportTable::new`, `ExportEntry` | Parsing de tabla de exportaciones y detección de Forwarded Exports (`[fwd]`) |
| **PE Parser** | `src/structures/pe/helpers.rs` | `read_cstr` | Lectura de cadenas ASCII terminadas en nulo |
| **PEB / TEB** | `src/structures/peb/peb.rs` | `Peb::get_ptr`, `detect_version` | Extracción de PEB (`GS:[0x60]` / `FS:[0x30]`) y clasificación de SO |
| **PEB Cargador** | `src/structures/peb/ldr.rs` | `PebLdrData`, `_PEB_LDR_DATA` | Estructuras del cargador dinámico en x64 y x86 |
| **PEB Cargador** | `src/structures/peb/ldr_entry.rs` | `LdrDataTableEntry` | Mapeo de módulos cargados y evolución histórica de campos (Vista a Win11) |
| **PEB Listas** | `src/structures/peb/list_entry.rs` | `ListEntry`, `containing_record`, `ListIter` | Navegación de listas dobles circulares y macro `CONTAINING_RECORD` |
| **PEB Offsets** | `src/structures/peb/offsets/` | `peb_x64.rs`, `peb_x86.rs` | Tablas de consulta exhaustivas de desplazamientos según versión del kernel |
| **Descubrimiento** | `src/techniques/discovery/process.rs` | `process_discovery`, `get_process_table` | Enumeración de procesos vía `NtQuerySystemInformation` y renderizado de tabla |
| **Evasión Hashing** | `src/techniques/evasion/api_hashing.rs` | `unique_hash` | Algoritmo FNV-1a modificado con ROR-7 y máscara XOR para ofuscación de cadenas |
| **Resolución API** | `src/techniques/evasion/dinamic_api_resolution.rs` | `get_ntdll_base`, `get_export_by_name_hash` | Localización de módulos en PEB y funciones en EAT sin APIs de Windows |
| **SSN Opcodes** | `src/techniques/evasion/syscall_opcodes.rs` | Constantes de SSNs Windows 10 x64 | Catálogo de referencia para validación estática de servicios del sistema |
| **SSN Dinámico** | `src/techniques/evasion/execution/dinamic_ssn.rs` | `get_dinamic_ssn` | Extracción en runtime de SSN en NTDLL y detección de ganchos (INT3 / NOP) |
| **Syscalls Directas** | `src/techniques/evasion/execution/direct_syscall.rs` | `direct_syscall_6` | Invocación directa mediante ensamblador en línea (`syscall` / `sysenter`) |
| **Invocación Dinámica** | `src/techniques/evasion/execution/dynamic_call.rs` | `dynamic_stdcall_by_name`, `dynamic_cdecl_by_name` | Envoltorios de llamada a funciones de NTDLL por nombre o hash |
| **Llamadas Normales** | `src/techniques/evasion/execution/normal_call.rs` | `call_cdecl`, `call_stdcall` | Invocación por aridad (0 a 10 argumentos) adaptada para x86 y x64 |
| **Syscalls Indirectas** | `src/techniques/evasion/execution/indirect_syscall.rs` | `indirect_syscall_6` | Despacho indirecto hacia gadget `syscall; ret` en NTDLL con stack spoofing |
| **Pila Sintética** | `src/techniques/evasion/stack_spoofing/call_stack_spoofing.rs` | `prepare_spoof_data`, `SpoofData` | Construcción del marco falso con `RtlUserThreadStart`, `BaseThreadInitThunk` y gadgets |
| **Unwind Info** | `src/techniques/evasion/stack_spoofing/unwind_info.rs` | `get_unwind_offsets`, `parse_pdata_entry` | Decodificación de directorios `.pdata` y opcodes de `UNWIND_INFO` en x64 |
| **Memoria Evasión** | `src/techniques/evasion/memory/write_process_mem_rw_rx.rs` | `write_process_mem_rw_rx` | Inyección en memoria remota mediante ciclo de transición RW $\rightarrow$ RX |
| **Cripto Claves** | `src/cipher/keys.rs` | `Identity`, `SymetricKey` | Generación de claves X25519 y derivación de secretos compartidos Diffie-Hellman |
| **Cripto AEAD** | `src/cipher/cipher_data.rs` | `CipherData::cipher`, `CipherData::decipher` | Cifrado y descifrado autenticado ChaCha20-Poly1305 (28B overhead) |
| **Cripto Handshake** | `src/cipher/handshake.rs` | `SecureClientHandshakePacket` | Handshake con anonimización de la clave pública estática del cliente (92B) |
| **Cripto Sesión** | `src/cipher/communication.rs` | `SecureDataPacket` | Envoltorio de mensajes cifrados para tráfico de sesión |
| **Binario Suite** | `src/bin/prueba.rs` | Flujo secuencial de 25 pasos | Demostración integral e integración end-to-end de todos los subsistemas |
| **Binario Spoofing** | `src/bin/prueba_call_spoofing.rs` | PoC aislada de 60 segundos | Retardo de hilo con `NtDelayExecution` mediante indirect syscall y stack spoofing |
