# Zada-Xor: Technical Reference Manual and Windows NT Internal Architecture

> **Languages / Idiomas:** **English** | [Español](README_ES.md)

**Zada-Xor** is a reverse engineering, memory forensics, and offensive/defensive security research framework implemented entirely in Rust. Its fundamental purpose lies in direct interaction with the native Windows NT subsystem (`ntoskrnl.exe` / `ntdll.dll`) in user mode (Ring 3), completely eschewing Microsoft-provided abstraction crates for Rust (`windows`, `windows-sys`, or `winapi`) as well as third-party PE parsers.

The project implements from scratch primitives for manual parsing of PE/PE32+ executable structures, undetectable traversal of loader lists in the Process Environment Block (PEB), dynamic resolution of System Service Numbers (SSN) via advanced in-memory disassembly techniques (Hell's Gate / Halo's Gate), dispatch of *Indirect Syscalls* combined with synthetic *Call Stack Spoofing*, and a production-grade cryptographic channel based on Diffie-Hellman key exchange over Curve25519 and AEAD ChaCha20-Poly1305 symmetric authenticated encryption.

---

## Disclaimer and Ethical Use

> [!IMPORTANT]
> **This repository was conceived and developed strictly for educational purposes, academic research, and the advancement of defensive security.**
>
> * **Authorized Scope:** The source code, compiled binaries, and technical documentation contained in this project are intended exclusively for experimentation in controlled laboratories, isolated virtual environments, and security audits where prior, explicit, and formal written authorization from system owners exists.
> * **Defensive Security Focus:** The documented techniques detail vectors leveraged by Advanced Persistent Threats (APTs) and modern malware to evade user-space monitoring hooks. Their analysis aims to enable security researchers, EDR/XDR developers, SOC analysts, and detection engineers to understand the underlying mechanics and build robust correlation rules, kernel-level telemetry (ETW-Ti), and behavioral signatures.
> * **Prohibition of Malicious Use:** The author does not endorse, promote, or assume responsibility for any misuse, destructive action, or unlawful activity carried out by third parties using this material. Executing these techniques against unauthorized infrastructure constitutes a violation of applicable laws and regulations.

> [!WARNING]
> Direct manipulation of internal Windows structures (`PEB`, `TEB`, `LDR`) and execution of indirect system calls involve architectural assumptions that may vary across kernel builds. Although the framework includes dynamic support for versions ranging from Windows Vista to Windows 11 25H2, uncontrolled alteration of process memory may induce host instability or process crashes.

---

## Table of Contents

- [Disclaimer and Ethical Use](#disclaimer-and-ethical-use)
- [Architectural Philosophy: Zero-Dependency Runtime](#architectural-philosophy-zero-dependency-runtime)
- [Repository Structure and Mapping](#repository-structure-and-mapping)
- [Low-Level Structures (`src/structures/`)](#low-level-structures-srcstructures)
  - [Manual PE Format Parsing (`src/structures/pe/`)](#manual-pe-format-parsing-srcstructurespe)
  - [Runtime Introspection: TEB / PEB / LDR (`src/structures/peb/`)](#runtime-introspection-teb--peb--ldr-srcstructurespeb)
    - [Extracting the PEB Without System APIs](#extracting-the-peb-without-system-apis)
    - [Dynamic Operating System Version Detection](#dynamic-operating-system-version-detection)
    - [PEB Offset Comparison on x64 (`peb_x64.rs`)](#peb-offset-comparison-on-x64-peb_x64rs)
    - [Loader Structures (`_PEB_LDR_DATA` and `_LDR_DATA_TABLE_ENTRY`)](#loader-structures-_peb_ldr_data-and-_ldr_data_table_entry)
    - [Circular Navigation with `_LIST_ENTRY` and `Iterator` Trait](#circular-navigation-with-_list_entry-and-iterator-trait)
- [Native NT Subsystem (`src/nt/`)](#native-nt-subsystem-srcnt)
  - [NT Kernel Types (`src/nt/types.rs`)](#nt-kernel-types-srcnttypesrs)
  - [Process Management (`src/nt/process/`)](#process-management-srcntprocess)
    - [`open_process.rs`](#open_processrs)
    - [`query_information_process.rs`](#query_information_processrs)
  - [Kernel Object Management (`src/nt/kernel_objects/`)](#kernel-object-management-srcntkernel_objects)
    - [`close.rs`](#closers)
    - [`query_object.rs`](#query_objectrs)
    - [`duplicate_object.rs`](#duplicate_objectrs)
  - [Advanced Virtual Memory Management (`src/nt/memory/`)](#advanced-virtual-memory-management-srcntmemory)
    - [`virtual_alloc.rs`](#virtual_allocrs)
    - [`read_process_mem.rs` and `write_process_mem.rs`](#read_process_memrs-and-write_process_memrs)
    - [`protect_virtual_mem.rs`](#protect_virtual_memrs)
    - [`query_virtual_mem.rs`](#query_virtual_memrs)
    - [`pattern_scan_mem.rs`: Signature Scanning and `.pdata` Boundary Delimitation](#pattern_scan_memrs-signature-scanning-and-pdata-boundary-delimitation)
- [Evasion and Discovery Techniques (`src/techniques/`)](#evasion-and-discovery-techniques-srctechniques)
  - [API Hashing and Static Obfuscation (`src/techniques/evasion/api_hashing.rs`)](#api-hashing-and-static-obfuscation-srctechniquesevasionapi_hashingrs)
    - [Precalculated Hashes and Constants](#precalculated-hashes-and-constants)
  - [Dynamic API Resolution (`src/techniques/evasion/dinamic_api_resolution.rs`)](#dynamic-api-resolution-srctechniquesevasiondinamic_api_resolutionrs)
  - [Dynamic SSN Extraction: Hell's Gate and Halo's Gate (`src/techniques/evasion/execution/dinamic_ssn.rs`)](#dynamic-ssn-extraction-hells-gate-and-halos-gate-srctechniquesevasionexecutiondinamic_ssnrs)
  - [Direct Syscall Dispatch (`src/techniques/evasion/execution/direct_syscall.rs`)](#direct-syscall-dispatch-srctechniquesevasionexecutiondirect_syscallrs)
- [Advanced Evasion: Indirect Syscalls and Call Stack Spoofing](#advanced-evasion-indirect-syscalls-and-call-stack-spoofing)
  - [Indirect Jump to `ntdll.dll`](#indirect-jump-to-ntdlldll)
  - [Call Stack Spoofing](#call-stack-spoofing)
    - [1. Decoding `.pdata` and `UNWIND_INFO` (`unwind_info.rs`)](#1-decoding-pdata-and-unwind_info-unwind_infors)
    - [2. Locating Gadgets in NTDLL](#2-locating-gadgets-in-ntdll)
    - [3. Synthetic Stack Layout at Runtime](#3-synthetic-stack-layout-at-runtime)
- [Complementary Invocation and Memory Techniques](#complementary-invocation-and-memory-techniques)
  - [Stealthy RW $\rightarrow$ RX Memory Injection (`write_process_mem_rw_rx.rs`)](#stealthy-rw-rightarrow-rx-memory-injection-write_process_mem_rw_rxrs)
  - [Dynamic Invocation Wrappers (`dynamic_call.rs` and `normal_call.rs`)](#dynamic-invocation-wrappers-dynamic_callrs-and-normal_callrs)
  - [Process Discovery and Introspection (`src/techniques/discovery/process.rs`)](#process-discovery-and-introspection-srctechniquesdiscoveryprocessrs)
- [Cryptographic Subsystem and Secure Channel (`src/cipher/`)](#cryptographic-subsystem-and-secure-channel-srccipher)
  - [Asymmetric Identity Management (`keys.rs`)](#asymmetric-identity-management-keysrs)
  - [AEAD ChaCha20-Poly1305 Symmetric Authenticated Encryption (`cipher_data.rs`)](#aead-chacha20-poly1305-symmetric-authenticated-encryption-cipher_datars)
    - [Payload Envelope Layout](#payload-envelope-layout)
  - [Handshake Protocol with Key Anonymization (`handshake.rs`)](#handshake-protocol-with-key-anonymization-handshakers)
- [Demonstration and Validation Binaries (`src/bin/`)](#demonstration-and-validation-binaries-srcbin)
  - [1. `src/bin/prueba.rs`: Comprehensive 25-Step Integration Suite](#1-srcbinpruebars-comprehensive-25-step-integration-suite)
  - [2. `src/bin/prueba_call_spoofing.rs`: Specialized Evasion PoC](#2-srcbinprueba_call_spoofingrs-specialized-evasion-poc)
- [Compilation, Optimization, and Laboratory Environments](#compilation-optimization-and-laboratory-environments)
  - [Optimization Profile in `Cargo.toml`](#optimization-profile-in-cargotoml)
  - [Cross-Compilation for Windows](#cross-compilation-for-windows)
  - [Lab Execution with Wine](#lab-execution-with-wine)
- [Summary Matrix of Files and Components](#summary-matrix-of-files-and-components)

---

## Architectural Philosophy: Zero-Dependency Runtime

One of the defining attributes of `zada-xor` is its **self-contained and autonomous** architecture:

1. **No External Windows SDKs:** The project does not utilize `winapi`, `windows-sys`, or `windows`. All interaction with the operating system—from retrieving the TEB pointer via segment registers to dispatching native calls—is implemented via C type definitions (`#[repr(C)]`), unaligned dereferences (`read_unaligned`), and inline assembly (`core::arch::asm!`).
2. **No Third-Party PE Parsers:** DOS and NT headers, Data Directories, Export Address Tables, and Exception Tables (`.pdata`) are parsed directly from raw memory pointers mapped into the address space.
3. **Strictly Contained Cryptographic Dependencies:** `Cargo.toml` restricts external dependencies to exclusively three specialized cryptographic crates for the communication channel:
   - `x25519-dalek` (v2.0.1): Pure Rust primitives for Diffie-Hellman key exchange over Curve25519.
   - `rand_core` (v0.6.4): Abstraction for operating system cryptographic entropy.
   - `chacha20poly1305` (v0.10): AEAD authenticated stream cipher implementation (RFC 8439).

> [!NOTE]
> **Author's Reflection on the Zero-Dependency Design:**
> My primary goal when structuring this project was to eliminate any predictable footprint in the Import Address Table (IAT) and binary metadata. When an analyst or detection engine inspects a standard Rust binary, they commonly find dozens of dependencies and revealing strings introduced by conventional SDKs. By discarding external libraries and manually resolving every structure starting from the `GS`/`FS` segment registers, the resulting binary depends on zero intermediate DLLs and interacts directly with the native NT subsystem.

---

## Repository Structure and Mapping

The project architecture is organized into five modular subsystems under `src/`:

```text
zada-xor/
├── Cargo.toml                              # Compilation profile, dependencies, and release optimizations
├── comandos                                # Cross-compilation scripts and Wine execution helpers
├── src/
│   ├── lib.rs                              # Library root; re-export of public modules
│   ├── utils.rs                            # Unaligned memory read primitives and Unicode string utilities
│   ├── bin/                                # Validation and demonstration executable binaries
│   │   ├── prueba.rs                       # Comprehensive 25-step sequential integration suite
│   │   └── prueba_call_spoofing.rs         # Specialized indirect syscall & call stack spoofing PoC
│   ├── cipher/                             # Cryptographic subsystem and secure channel protocol
│   │   ├── mod.rs                          # Module export for cryptographic primitives
│   │   ├── keys.rs                         # X25519 asymmetric identities and secret derivation
│   │   ├── cipher_data.rs                  # ChaCha20-Poly1305 authenticated encryption engine
│   │   ├── handshake.rs                    # Handshake protocol with public key anonymization
│   │   └── communication.rs                # Encrypted session payload carrier
│   ├── nt/                                 # Native Windows NT subsystem (Kernel & NTDLL)
│   │   ├── mod.rs                          # NT kernel submodule declarations
│   │   ├── types.rs                        # Base types, access masks, and NTSTATUS constants
│   │   ├── process/                        # Native process operations
│   │   │   ├── mod.rs
│   │   │   ├── open_process.rs             # NtOpenProcess with CLIENT_ID and OBJECT_ATTRIBUTES
│   │   │   └── query_information_process.rs # NtQueryInformationProcess and handle table enumeration
│   │   ├── kernel_objects/                 # Kernel object lifecycle management
│   │   │   ├── mod.rs
│   │   │   ├── close.rs                    # Indirect invocation of NtClose
│   │   │   ├── duplicate_object.rs         # Planned stub for NtDuplicateObject
│   │   │   └── query_object.rs             # NtQueryObject with dynamic buffer resizing
│   │   └── memory/                         # Advanced virtual memory management and scanning
│   │       ├── mod.rs
│   │       ├── virtual_alloc.rs            # NtAllocateVirtualMemory (MEM_COMMIT, MEM_RESERVE)
│   │       ├── read_process_mem.rs         # NtReadVirtualMemory
│   │       ├── write_process_mem.rs        # NtWriteVirtualMemory
│   │       ├── protect_virtual_mem.rs      # NtProtectVirtualMemory and page boundary alignment
│   │       ├── query_virtual_mem.rs        # NtQueryVirtualMemory and visual address space mapper
│   │       └── pattern_scan_mem.rs         # Signature scanning, .pdata bounds, and OsRng randomization
│   ├── structures/                         # Manual parsing of binary and internal structures
│   │   ├── mod.rs
│   │   ├── pe/                             # Manual parsing of Portable Executable (PE / PE32+)
│   │   │   ├── mod.rs
│   │   │   ├── constants.rs                # PE magic numbers, signatures, and fixed offsets
│   │   │   ├── headers.rs                  # Parsing DOS and NT headers (PeHeaderInfo)
│   │   │   ├── optional_header.rs          # ImageOptionalHeader64 and memory alignment validation
│   │   │   ├── export.rs                   # ExportTable, ordinal resolution, and Forwarded Exports
│   │   │   └── helpers.rs                  # Null-terminated C-string reading (read_cstr)
│   │   └── peb/                            # Introspection of TEB, PEB, and dynamic loader (LDR)
│   │       ├── mod.rs
│   │       ├── peb.rs                      # Peb, reading GS:[0x60]/FS:[0x30], and OS detection
│   │       ├── ldr.rs                      # Structure _PEB_LDR_DATA (x64 and x86)
│   │       ├── ldr_entry.rs                # Historical evolution of _LDR_DATA_TABLE_ENTRY (Vista to Win11)
│   │       ├── list_entry.rs               # _LIST_ENTRY, containing_record, and ListIter iterator
│   │       └── offsets/                    # Exhaustive offset lookup tables
│   │           ├── mod.rs
│   │           ├── peb_x64.rs              # PEB offsets for Vista, Win7, Win8, Win10, and Win11
│   │           └── peb_x86.rs              # PEB offsets for XP, Vista, Win7, Win8, and Win10
│   └── techniques/                         # Defense evasion and discovery mechanisms
│       ├── mod.rs
│       ├── discovery/                      # Process discovery and introspection
│       │   ├── mod.rs
│       │   └── process.rs                  # Enumeration via NtQuerySystemInformation with ASCII table
│       └── evasion/                        # Evasion mechanisms and covert execution
│           ├── mod.rs
│           ├── api_hashing.rs              # Modified FNV-1a hashing with ROR-7 and XOR masking
│           ├── dinamic_api_resolution.rs   # Module resolution in PEB and EAT export search by hash
│           ├── syscall_opcodes.rs          # Reference catalog of Windows 10 x64 SSNs
│           ├── execution/                  # Execution engines and syscall dispatchers
│           │   ├── mod.rs
│           │   ├── dinamic_ssn.rs          # Dynamic SSN extraction and EDR hook detection
│           │   ├── direct_syscall.rs       # Direct syscalls via inline assembly (x64 and x86)
│           │   ├── dynamic_call.rs         # Stdcall and cdecl dynamic wrappers by name or hash
│           │   ├── indirect_syscall.rs     # Indirect syscalls combined with Call Stack Spoofing
│           │   └── normal_call.rs          # Typed arity-based invocation of cdecl and stdcall pointers
│           ├── memory/                     # Stealthy memory manipulation
│           │   ├── mod.rs
│           │   └── write_process_mem_rw_rx.rs # Process memory injection via RW -> RX transition cycle
│           └── stack_spoofing/             # Synthetic stack spoofing engine
│               ├── mod.rs
│               ├── call_stack_spoofing.rs  # Fake frame synthesis and ROP gadget locator
│               └── unwind_info.rs          # .pdata parser and UNWIND_INFO opcode decoder
```

---

## Low-Level Structures (`src/structures/`)

### Manual PE Format Parsing (`src/structures/pe/`)

Executable analysis is performed entirely over the memory of loaded modules using raw pointer arithmetic:

1. **DOS and NT Headers (`headers.rs`):**
   - The offset to the NT header is read at `base + 0x3C` (`e_lfanew`).
   - The signature `IMAGE_NT_SIGNATURE` (`0x4550`, corresponding to `"PE\0\0"`) is verified.
   - The optional header is located by computing `nt_headers_ptr + NT_SIGNATURE_SIZE (4) + FILE_HEADER_SIZE (20)`.
   - The magic number is inspected: `PE32_MAGIC` (`0x010B`) or `PE32_PLUS_MAGIC` (`0x020B`).
2. **Optional Header and Alignment Validation (`optional_header.rs`):**
   - Maps `ImageOptionalHeader64` along with its 16 `ImageDataDirectory` entries.
   - **Strict Memory Alignment Check:** Before casting a memory address to a Rust reference, alignment is verified:
     ```rust
     if optional_header_base_addr % std::mem::align_of::<ImageOptionalHeader64>() != 0 {
         return Err("Address is not aligned");
     }
     ```
3. **Export Address Table and Forwarded Exports (`export.rs`):**
   - Locates `IMAGE_EXPORT_DIRECTORY` from Data Directory 0 (`export_directory_offset`: `0x70` in PE32+, `0x60` in PE32).
   - Reads the three fundamental tables: `AddressOfFunctions`, `AddressOfNames`, and `AddressOfNameOrdinals`.
   - **Forwarded Export Detection:** If a function's RVA falls inside the physical range of the export directory `[exp_rva, exp_rva + exp_size)`, the address does not point to executable code, but to an ASCII string referencing a function in another DLL (for example, `NTDLL.RtlAllocateHeap`). The parser detects this condition, sets `va = null`, and stores the reference with the prefix `[fwd] <dll>.<func>`:
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

### Runtime Introspection: TEB / PEB / LDR (`src/structures/peb/`)

#### Extracting the PEB Without System APIs
The Thread Environment Block (TEB) contains a pointer to the Process Environment Block (PEB). It is retrieved at compile-time via architecture-specific inline assembly:
- **x86_64 Architecture:** Segment register `GS` at offset `0x60`:
  ```rust
  #[cfg(target_arch = "x86_64")]
  unsafe {
      asm!("mov {0}, gs:[0x60]", out(reg) pebdir, options(nomem, nostack));
  }
  ```
- **x86 Architecture:** Segment register `FS` at offset `0x30`:
  ```rust
  #[cfg(target_arch = "x86")]
  unsafe {
      asm!("mov {0}, fs:[0x30]", out(reg) pebdir, options(nomem, nostack));
  }
  ```

#### Dynamic Operating System Version Detection
Because the internal layout of the PEB changes across Windows builds, a two-phase bootstrapping mechanism is used:
1. `OSMajorVersion` and `OSBuildNumber` fields have remained at fixed offsets since Windows Vista on both x64 (`0x118` and `0x120`) and x86 (`0x0A4` and `0x0AC`).
2. These fields are read to classify the operating system:
   - `build >= 22000` $\rightarrow$ Windows 11
   - `major == 10` $\rightarrow$ Windows 10
   - `major == 6 && build >= 9200` $\rightarrow$ Windows 8
   - `major == 6 && build >= 7600` $\rightarrow$ Windows 7
   - In any other case $\rightarrow$ Windows Vista
3. The table `PebOffsets` is loaded dynamically with the exact memory offsets matching the active OS version.

#### PEB Offset Comparison on x64 (`peb_x64.rs`)

| Field | Vista (0x368) | Win 7 (0x380) | Win 8 (0x388) | Win 10 22H2 (0x7C8) | Win 11 25H2 (0x7D0) |
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

#### Loader Structures (`_PEB_LDR_DATA` and `_LDR_DATA_TABLE_ENTRY`)
- **`_PEB_LDR_DATA`:** Total size is `0x58` bytes on x64 and `0x30` bytes on x86. It holds the heads of the three doubly-linked lists of the loader: `InLoadOrderModuleList`, `InMemoryOrderModuleList`, and `InInitializationOrderModuleList`.
- **Evolution of `_LDR_DATA_TABLE_ENTRY`:** The structure representing each loaded module expanded across Windows versions:
  - Windows Vista: `0xC8` bytes.
  - Windows 7: `0xE0` bytes (introduced `OriginalBase` and `LoadTime`).
  - Windows 8: `0x110` bytes (replaced lists with directed acyclic graphs and balanced nodes).
  - Windows 10 22H2: `0x120` bytes (added `DependentLoadFlags` and `SigningLevel`).
  - Windows 11 24H2+: `0x138` bytes (added `CheckSum`, `ActivePatchImageBase`, and `HotPatchState`).

#### Circular Navigation with `_LIST_ENTRY` and `Iterator` Trait
Windows NT kernel linked lists are circular. To prevent infinite loops and dereference entries idiomatically:
1. Container record calculation is implemented (equivalent to the C `CONTAINING_RECORD` macro):
   ```rust
   pub unsafe fn containing_record(&self, field_offset: usize) -> *const u8 {
       unsafe { self.ptr.sub(field_offset) }
   }
   ```
2. The `ListIter` iterator is implemented over `_LIST_ENTRY`, halting iteration when the current pointer returns to `head` or becomes null, enabling safe traversal of modules in Rust:
   ```rust
   for node in head.iter() {
       let entry_ptr = ListEntry::new(node).containing_record(ldr_off::IN_LOAD_ORDER_LINKS);
       let entry = LdrDataTableEntry::new(entry_ptr);
       // Safe module introspection...
   }
   ```

---

## Native NT Subsystem (`src/nt/`)

The `src/nt/` module provides direct wrappers around native kernel system calls without intermediaries.

### NT Kernel Types (`src/nt/types.rs`)
Defines native primitive kernel types: `HANDLE`, `SIZE_T`, `ULONG`, `LONG`, `ACCESS_MASK`, `LARGE_INTEGER`, `GENERIC_MAPPING`, and the error status `STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820` (signed representation of `0xC0000004`).

### Process Management (`src/nt/process/`)

#### `open_process.rs`
- **API Hash:** `0xaddc1c2e` (`NtOpenProcess`).
- **Access Mask (`DESIRED_ACCESS`):** Defines `PROCESS_ALL_ACCESS` (`0x0410`), `PROCESS_VM_READ` (`0x0010`), `PROCESS_VM_WRITE` (`0x0020`), `PROCESS_VM_OPERATION` (`0x0008`), and `PROCESS_QUERY_INFORMATION` (`0x0400`), implementing the `BitOr` trait for bitwise combination via the `|` operator.
- **Required Structures:** Configures `CLIENT_ID` (placing the target PID in `unique_process`) and `OBJECT_ATTRIBUTES` (setting `length` to the structure size: 48 bytes on x64, 24 bytes on x86).
- **Dispatch:** Dynamically resolves the SSN for `NtOpenProcess` and dispatches the indirect syscall via `indirect_syscall_6`.

#### `query_information_process.rs`
- **API Hash:** `0x6fa0c1f4` (`NtQueryInformationProcess`).
- **Handle Table Enumeration:** Queries the `ProcessHandleInformation` class (`51`).
- **Dynamic Reallocation Loop:** Because process handle counts fluctuate continuously, up to 10 retries are executed upon receiving `STATUS_INFO_LENGTH_MISMATCH` (`0xC0000004`). If the kernel supplies the required length, a safety margin (*slack*) of `16 * size_of::<PROCESS_HANDLE_TABLE_ENTRY_INFO>()` is appended; if it returns 0, the previous buffer size is doubled.
- **Visualization:** `print_all_handles_info(handle)` deserializes `PROCESS_HANDLE_SNAPSHOT_INFORMATION` and displays handle values, granted access rights (`GrantedAccess`), and object type indices in the console.

### Kernel Object Management (`src/nt/kernel_objects/`)

#### `close.rs`
- **API Hash:** `0x1c0fcdc4` (`NtClose`).
- Invokes the indirect syscall to release kernel object handles, validating return code `STATUS_SUCCESS` (`0`).

#### `query_object.rs`
- **API Hash:** `0xfc2a599c` (`NtQueryObject`).
- **Information Classes:** Models `OBJECT_INFORMATION_CLASS` (`ObjectBasicInformation = 0`, `ObjectNameInformation = 1`, `ObjectTypeInformation = 2`, `ObjectTypesInformation = 3`, `ObjectHandleFlagInformation = 4`, etc.).
- **Probing and Dynamic Sizing:**
  - `query_object_find_struct_size`: Performs an initial probe with a null buffer and size 0, capturing `STATUS_INFO_LENGTH_MISMATCH` (`0xC0000004`) or `STATUS_BUFFER_TOO_SMALL` (`0xC0000023`) to discover the exact buffer size required by the kernel.
  - `query_object_size_solved`: Manages an allocation loop of up to 20 retries with headroom until successfully querying object types (`OBJECT_TYPES_INFORMATION`).

#### `duplicate_object.rs`
- **Audit Status:** Currently contains the commented placeholder declaration `// Implementación futura de NtDuplicateObject`. It is cataloged as a planned capability for future development iterations.

### Advanced Virtual Memory Management (`src/nt/memory/`)

#### `virtual_alloc.rs`
- **API Hash:** `0x2759addf` (`NtAllocateVirtualMemory`).
- Enums `AllocationType` (`MEM_COMMIT = 0x1000`, `MEM_RESERVE = 0x2000`, `MEM_RESET`, `MEM_TOP_DOWN`) and `PageProtection` (`PAGE_READONLY`, `PAGE_READWRITE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`).
- Handles input/output pointer references for base address and allocation size.

#### `read_process_mem.rs` and `write_process_mem.rs`
- **API Hashes:** `0x7a58c6ca` (`NtReadVirtualMemory`) and `0x7f603ee9` (`NtWriteVirtualMemory`).
- Performs atomic memory read and write operations on local or remote processes, returning the exact number of bytes transferred.

#### `protect_virtual_mem.rs`
- **API Hash:** `0x96e11bf8` (`NtProtectVirtualMemory`).
- Modifies page protection attributes while accounting for kernel page-boundary rounding (returning `(boundary_address, boundary_size, old_protect)`).

#### `query_virtual_mem.rs`
- **API Hash:** `0xbe409009` (`NtQueryVirtualMemory`).
- Queries memory region attributes via `MEMORY_BASIC_INFORMATION` (incorporating `PartitionId: u16` on x64).
- **Visual Memory Mapper (`escanear_memoria_proceso`):** Scans the entire user-mode address space (from `0x00000` to `0x7FFFFFFFFFFF`). For every region in `MEM_COMMIT` state, it maps protection flags into compact identifiers (`RW`, `RWX`, `RX`, `RO`, `X`) and prints a structured Unicode table showing base addresses, region sizes, and execution attributes.

#### `pattern_scan_mem.rs`: Signature Scanning and `.pdata` Boundary Delimitation
- `mem_remote_pattern_find`: Scans remote process memory using sliding byte windows (`buffer.windows()`).
- `mem_local_pattern_find`: Concurrently searches for multiple byte patterns within local address ranges without requiring alignment.
- `get_pdata_func_info`: Queries the `.pdata` exception directory to locate the precise start (`begin_address`) and end (`end_address`) of legitimate functions.
- `pdata_pattern_find_starting_at_rand_func`: Iterates over the total set of functions in `.pdata`, selects a randomized initial index using `rand_core::OsRng`, and traverses DLL functions circularly. This technique avoids linear, sequential scanning patterns that trigger telemetry alerts.
- `find_pattern_in_specific_func`: Constrains byte searches to the exact bounds of a function identified by its RVA (utilized to locate the `syscall; ret` gadget).

---

## Evasion and Discovery Techniques (`src/techniques/`)

### API Hashing and Static Obfuscation (`src/techniques/evasion/api_hashing.rs`)

To prevent plaintext strings from appearing in binaries—where tools like `strings` or YARA rules can detect them—a custom variation of FNV-1a is implemented:

```rust
#[inline]
pub fn unique_hash(name: &str) -> u32 {
    let bytes = name.as_bytes();
    let mut hash: u32 = 0x811C9DC5; // FNV offset basis
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(16777619); // FNV prime
        hash = (hash >> 7) | (hash << (32 - 7)); // Circular right bit rotation (ROR 7)
        i += 1;
    }
    hash ^ 0x7F3A9C12 // Final XOR mask
}
```

#### Precalculated Hashes and Constants

| Target String | Resulting 32-Bit Hash |
|---|---|
| `"ntdll.dll"` (lowercase) | `0x68861c6f` |
| `"kernel32.dll"` (lowercase) | `0xd32210ae` |
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

### Dynamic API Resolution (`src/techniques/evasion/dinamic_api_resolution.rs`)
Enables resolving modules and functions in memory without interacting with the IAT:
- `get_ntdll_base()` and `get_kernel32_base()`: Traverse `InLoadOrderModuleList` from the PEB and match hashes against lowercase module names.
- `get_dll_base_by_hash(hash: u32)`: Locates any loaded DLL using its FNV-1a/ROR hash.
- `get_export_by_name` and `get_export_by_name_hash`: Parse the target module's export table to recover the function's virtual address.

### Dynamic SSN Extraction: Hell's Gate and Halo's Gate (`src/techniques/evasion/execution/dinamic_ssn.rs`)

Hardcoding System Service Numbers (SSN) is fragile because Microsoft frequently changes them across minor updates and kernel builds. The `dinamic_ssn.rs` module extracts the SSN at runtime by analyzing the machine code of the function prologue in `ntdll.dll`:

1. **Standard x64 Windows Stub Pattern:** The typical beginning of a native syscall stub in NTDLL presents the following bytes:
   ```text
   4C 8B D1         mov r10, rcx
   B8 XX XX 00 00   mov eax, <SSN>
   ```
2. **Opcode Inspection:** Locates the `0xB8` opcode and verifies that the preceding 3 bytes match `[0x4C, 0x8B, 0xD1]`. The 32-bit immediate value following `0xB8` is extracted as the genuine SSN.
3. **EDR Hook Detection:** If an endpoint security solution has placed a hook in the function prologue:
   - Presence of 3 consecutive `0xCC` bytes (`INT3` / debug breakpoint).
   - Presence of 2 consecutive `0x90` bytes (`NOP` sled preceding a `JMP` redirection).
   - The function terminates the extraction attempt and signals hook detection, allowing Halo's Gate logic to inspect adjacent function stubs above or below to deduce the SSN mathematically.

> [!NOTE]
> **Author's Reflection on WoW64 and 64-Bit Design Decision:**
> In the source code, I recorded an explicit design rationale regarding architectural scope:
> *"Indirect syscalls are only implemented for x64 because in x86 under a WoW64 environment, one would need to implement Heaven's Gate to transition into 64-bit NT syscalls, which introduces significant instability"*.
> In modern 64-bit operating systems, a 32-bit process running under the WoW64 emulator does not execute direct 32-bit syscalls into the kernel; instead, it traverses a compatibility gateway (*Heaven's Gate*) by switching the code segment descriptor to `0x33` to reach 64-bit `ntdll.dll`. Consequently, all indirect syscall and stack spoofing infrastructure was focused on x86_64, where EDR telemetry actively inspects 64-bit frame unwinding.

### Direct Syscall Dispatch (`src/techniques/evasion/execution/direct_syscall.rs`)
Implements `direct_syscall_6` using inline assembly for x64 (setting up the 32-byte shadow space, fifth and sixth arguments on the stack, and the `syscall` instruction) and for x86 (pushing arguments and executing `sysenter`).

---

## Advanced Evasion: Indirect Syscalls and Call Stack Spoofing

When an application invokes a `syscall` instruction directly from its own private memory section (`.text`), kernel-level telemetry drivers (such as Microsoft-Windows-Threat-Intelligence / ETW-Ti) and thread-sampling engines observe that the transition originated outside `ntdll.dll`'s address space. This anomaly immediately triggers detection alerts in EDR solutions.

To neutralize this telemetry vector, `zada-xor` pairs **Indirect Syscalls** with **Synthetic Call Stack Spoofing** guided by `.pdata` exception metadata.

### Indirect Jump to `ntdll.dll`
Instead of executing `syscall` within private memory:
1. A legitimate `syscall; ret` instruction sequence (`0x0F, 0x05, 0xC3`) is located inside the target function in `ntdll.dll` using `find_pattern_in_specific_func`.
2. An unconditional `jmp` directs execution to that instruction within NTDLL. As a result, the processor's `RIP` register during the transition to Ring 0 legitimately belongs to Microsoft's digitally signed NTDLL code segment.

### Call Stack Spoofing

The stack spoofing engine deceives stack walking algorithms (such as `RtlVirtualUnwind`) by synthesizing a call stack that appears to have originated in standard Windows thread entry points.

#### 1. Decoding `.pdata` and `UNWIND_INFO` (`unwind_info.rs`)
On Windows x64, every function that allocates stack space or implements exception handling must register a 12-byte `IMAGE_RUNTIME_FUNCTION_ENTRY` record in the `.pdata` section. The `unwind_info.rs` engine decodes the `ImageUnwindInfo` header and its 2-byte `UNWIND_CODE` entries:
- **Opcode 0 (`UWOP_PUSH_NONVOL`):** Adds 8 bytes to the stack (`push <reg>`).
- **Opcode 1 (`UWOP_ALLOC_LARGE`):** Adds `slot * 8` bytes (if `info == 0`) or a 32-bit value (if `info == 1`).
- **Opcode 2 (`UWOP_ALLOC_SMALL`):** Adds `(info * 8) + 8` bytes (between 8 and 128 bytes).
- **Opcodes 4 and 8 (`UWOP_SAVE_NONVOL`):** Saves registers via `mov` without altering stack allocation size.
- **Opcode 10 (`UWOP_PUSH_MACHFRAME`):** Adds 40 or 48 bytes (hardware interrupt frames).
- **Chained Unwind Info (`UNW_FLAG_CHAININFO`):** Recursively follows pointers to secondary `UNWIND_INFO` structures.

> [!NOTE]
> **Author's Reflection on the Dynamic Unwinding Engine:**
> The most complex challenge when engineering this evasion module was eliminating hardcoded stack offsets. Many public proof-of-concepts assume that `BaseThreadInitThunk` always allocates a fixed number of bytes. However, across various builds of Windows 10 and Windows 11, cumulative updates regularly alter function prologues and modify frame sizes. Building a full `.pdata` parser that decodes `UNWIND_CODE` opcodes in memory guarantees that the synthetic stack allocation mathematically mirrors what the OS unwinder expects, avoiding catastrophic stack misalignments upon return.

#### 2. Locating Gadgets in NTDLL
Using `prepare_gadget_spoof_data`, two gadgets are resolved within legitimate NTDLL memory:
- **Gadget 1:** `ADD RSP, 0x38; RET` (byte sequence `[0x48, 0x83, 0xC4, 0x38, 0xC3]`), verifying via `.pdata` that the enclosing function allocates a stack frame of exactly 56 bytes (`0x38`).
- **Gadget 2:** `CALL <AnchorReg>` (where the anchor register can be `RDI`, `RSI`, `R15`, or `R12`), allowing our code to regain execution flow after the call without polluting the stack with an illegitimate return address.

#### 3. Synthetic Stack Layout at Runtime

```text
================================================================================
[RSP + pos4] (Base)          -> Address of Gadget 1: ADD RSP, 0x38; RET
                                (Syscall in NTDLL executes RET and lands here)
[RSP + 0x08]                 -> Shadow Space 1 (Garbage / RCX)
[RSP + 0x10]                 -> Shadow Space 2 (Garbage / RDX)
[RSP + 0x18]                 -> Shadow Space 3 (Garbage / R8)
[RSP + 0x20]                 -> Shadow Space 4 (Garbage / R9)
[RSP + 0x28]                 -> Syscall Argument 5
[RSP + 0x30]                 -> Syscall Argument 6
================================================================================
...                          -> Gadget 1 executes "ADD RSP, 0x38", cleaning the
                                previous 56 bytes, then executes "RET".
================================================================================
[RSP + pos3] (offset4 + 8)   -> Address of Gadget 2: CALL <AnchorReg>
                                (Lands here. CALL returns control to Rust)
================================================================================
...                          -> Frame space allocated for Gadget 2 (per .pdata)
================================================================================
[RSP + pos2]                 -> Legitimate Address: BaseThreadInitThunk + 0x14
================================================================================
...                          -> Frame space for BaseThreadInitThunk (per .pdata)
================================================================================
[RSP + pos1]                 -> Legitimate Address: RtlUserThreadStart + 0x21
================================================================================
...                          -> Frame space for RtlUserThreadStart (per .pdata)
================================================================================
[RSP + null_ret_offset]      -> 0x0000000000000000 (NULL RETURN ADDRESS)
                                (Stack walker encounters 0x0 and concludes the
                                 thread originated cleanly at process entry).
================================================================================
```

*Note on Simulated Return Addresses:* Offsets `+0x21` for `RtlUserThreadStart` and `+0x14` for `BaseThreadInitThunk` are intentionally introduced. If return addresses pointed to offset 0 of those functions, security monitors would instantly identify the forgery, since a real `CALL` instruction never returns to the beginning of an enclosing function.

---

## Complementary Invocation and Memory Techniques

### Stealthy RW $\rightarrow$ RX Memory Injection (`write_process_mem_rw_rx.rs`)
Directly allocating memory regions with simultaneous Read, Write, and Execute permissions (`PAGE_EXECUTE_READWRITE` / RWX) represents one of the strongest heuristics in memory scanners.
The `write_process_mem_rw_rx` module implements a three-phase lifecycle:
1. **Phase 1 (RW Allocation):** Allocates memory with `PAGE_READWRITE` permissions via `nt_allocate_virtual_memory`.
2. **Phase 2 (Payload Write):** Transfers the payload using `nt_write_virtual_memory`.
3. **Phase 3 (RX Transition):** Changes memory protection to `PAGE_EXECUTE_READ` via `nt_protect_virtual_memory`.
The memory region never exists with concurrent write and execute permissions.

### Dynamic Invocation Wrappers (`dynamic_call.rs` and `normal_call.rs`)
Enable calling exported functions in `ntdll.dll` using both `cdecl` and `stdcall` conventions, unpacking up to 10 arguments:
- **x86 Architecture:** In `stdcall`, the callee cleans the stack (`ret N`), whereas in `cdecl`, the caller cleans `ESP`. To avoid stack corruption, `normal_call.rs` implements an exhaustive arity-based dispatcher (`match args.len()`) that transmutes function pointers into exact signatures accepting 0 to 9 parameters.
- **x64 Architecture:** Because the Microsoft x64 ABI unifies calling conventions using registers `RCX`, `RDX`, `R8`, `R9` and the stack for subsequent parameters, calls transmute directly into generic 10-argument function pointers.

### Process Discovery and Introspection (`src/techniques/discovery/process.rs`)
Enumerates active processes without relying on high-level APIs (`CreateToolhelp32Snapshot` or `EnumProcesses`):
1. Dynamically extracts the SSN for `NtQuerySystemInformation` (hash `0xc3d78064`).
2. Invokes the indirect syscall querying `SystemProcessInformation` (`5`).
3. Checks for `STATUS_INFO_LENGTH_MISMATCH` (`0xC0000004`), dynamically allocates native heap memory (`std::alloc::alloc`) with an 8 KB buffer margin (`+ 0x2000`) to absorb concurrently created processes, and executes a second call to populate process data.
4. Parses `SystemProcessInformation` entries, extracting PID, PPID, thread counts, open handles, private working set size, and executable names (`image_name.to_string()`).
5. `get_process_table()` renders process telemetry into a structured console table with Unicode box-drawing characters.

---

## Cryptographic Subsystem and Secure Channel (`src/cipher/`)

The `src/cipher/` module establishes an end-to-end encrypted and authenticated communication channel between the agent and a C2 server.

```text
+---------------------------------------------------------------------------------------+
| CLIENT                                                           SERVER               |
|                                                                                       |
| 1. Generates Ephemeral Secret (sk_e)                                                  |
|    Derives Ephemeral Public Key (pk_e)                                                |
| 2. Computes SS = ECDH(sk_e, pk_server_static)                                         |
| 3. Temporal Symmetric Key K_temp = SS                                                 |
| 4. Encrypts Real Static Public Key:                                                   |
|    Ciphered_Client_Pub = K_temp.cipher(pk_client_static)                              |
| 5. Transmits Handshake Packet (92 Bytes total):                                       |
|    [ pk_e (32B) ] + [ Ciphered_Client_Pub (60B: 12B nonce + 32B pub + 16B tag) ]      |
|    =======================================================>                           |
|                                                              6. Receives pk_e         |
|                                                              7. Computes SS =         |
|                                                                 ECDH(sk_server, pk_e) |
|                                                              8. Derives K_temp = SS   |
|                                                              9. Decrypts & validates: |
|                                                                 pk_client_static =    |
|                                                                 K_temp.decipher(...)  |
|                                                              10. Session Established  |
+---------------------------------------------------------------------------------------+
```

### Asymmetric Identity Management (`keys.rs`)
- **`Identity`:** Represents long-term identity. Generates a static private key (`StaticSecret`) via `OsRng` and derives its associated public key (`PublicKey`) on Curve25519.
- **`SymetricKey`:** Computes a 32-byte shared secret (`[u8; 32]`) via X25519 Diffie-Hellman (`my_secret.diffie_hellman(their_public)`). Consumes ownership (`move`) of the ephemeral secret to ensure immediate destruction in memory.

### AEAD ChaCha20-Poly1305 Symmetric Authenticated Encryption (`cipher_data.rs`)

> [!NOTE]
> **Author's Reflection on Choosing ChaCha20-Poly1305:**
> In the source comments, I noted:
> *"I implement encryption and decryption of payloads using ChaCha20 to move away from typical XOR schemes"*.
> In mainstream malware research, communication channels and configuration obfuscation frequently rely on static or rolling XOR algorithms. These mechanisms lack mathematical integrity and are trivially defeated by frequency analysis or Known Plaintext Attacks (KPA). Adopting ChaCha20-Poly1305 guarantees a high-performance stream cipher that does not require dedicated hardware acceleration (unlike AES-NI) and integrates a 128-bit Poly1305 MAC tag to verify packet integrity and authenticity.

#### Payload Envelope Layout

Every encrypted message is serialized with a fixed 28-byte overhead header:

| Offset (Bytes) | Length | Field | Description |
|---|---|---|---|
| `0x00 .. 0x0B` | 12 bytes | **Nonce** | 96-bit random initialization vector generated via `OsRng` |
| `0x0C .. (0x0C + N - 1)` | $N$ bytes | **Ciphertext** | Payload encrypted under the ChaCha20 keystream |
| `(0x0C + N) .. End` | 16 bytes | **Poly1305 Tag** | 128-bit Message Authentication Code (MAC) |

Upon decryption, the engine validates that the incoming buffer contains at least 12 bytes, splits the nonce, and passes the ciphertext along with its tag to the authenticator. If any byte is modified in transit, verification fails immediately and the packet is rejected.

### Handshake Protocol with Key Anonymization (`handshake.rs`)

In an operational deployment, the client possesses the server's public key. However, transmitting its own static public key in plaintext to authenticate would expose the agent's identity to network sensors and NTA appliances.
To guarantee anonymity:
1. The client generates a unique ephemeral key pair for the handshake.
2. Derives a temporary shared secret against the server's public key.
3. Encrypts its genuine static public key using that temporary secret.
4. Transmits `SecureClientHandshakePacket`:
   - 32 bytes of ephemeral public key in plaintext.
   - 60 bytes of encrypted static public key (12B nonce + 32B public key + 16B Poly1305 tag).
   - **Total transmission payload:** **92 bytes**.
5. The server receives the ephemeral public key, computes the identical temporary shared secret, and decrypts the client's genuine public key, establishing the encrypted session.

---

## Demonstration and Validation Binaries (`src/bin/`)

The repository includes two standalone executable binaries designed to validate all implemented modules.

### 1. `src/bin/prueba.rs`: Comprehensive 25-Step Integration Suite

This binary sequentially runs a comprehensive end-to-end integration test:

1. **Identification:** Displays current process PID via `std::process::id()`.
2. **API Hashing:** Computes the FNV-1a hash of `"NtQueryObject"`, verifying the expected result `0xfc2a599c`.
3. **Process Discovery:** Executes `get_process_table()`, invoking `NtQuerySystemInformation` via indirect syscall and rendering the process table.
4. **Interaction:** Prompts the operator for a target PID for memory manipulation tests.
5. **Process Handle Acquisition:** Calls `open_process` with access mask `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION` via indirect syscall `NtOpenProcess` (hash `0xaddc1c2e`).
6. **Kernel Object Introspection:** Calls `query_object_size_solved` with `OBJECT_INFORMATION_CLASS::ObjectTypesInformation`, exercising dynamic buffer reallocation.
7. **Handle Enumeration:** Executes `print_all_handles_info`, listing open handles and their granted permissions.
8. **Stealth Memory Injection:** Executes `write_process_mem_rw_rx`, allocating memory in `PAGE_READWRITE`, writing `"RustInternals123"`, and changing protection to `PAGE_EXECUTE_READ`.
9. **Manual PE Parsing:** Resolves `ntdll.dll` base via the PEB and parses PE headers using `PeHeaderInfo::parse_headers`.
10. **Key Generation:** Instantiates `Identity` for client and server and synthesizes the handshake packet.
11. **Hash Verification:** Prints precomputed hashes for system functions (`"RtlUserThreadStart"`, `"BaseThreadInitThunk"`, `"NtClose"`).
12. **Initial Memory Mapping:** Executes `escanear_memoria_proceso`, displaying mapped `MEM_COMMIT` regions and their protection flags.
13. **Read/Write Verification:** Reads injected memory via `nt_read_virtual_memory`, overwrites it with `"Terobolavariable"` via `nt_write_virtual_memory`, and reads back to verify modification.
14. **RWX Modification:** Updates page protection to `ExecuteReadWrite` using `nt_protect_virtual_memory`.
15. **Updated Memory Mapping:** Re-runs `escanear_memoria_proceso`, showing the region transitioned to `RWX`.
16. **Handle Teardown:** Closes the process handle with `nt_close` via indirect syscall `NtClose` (hash `0x1c0fcdc4`).
17. **Handshake Completion:** The server processes `SecureClientHandshakePacket`, decrypts the client key, and verifies equality of derived symmetric session keys.
18. **Encrypted Data Channel:** Encrypts and decrypts a plaintext payload using `SecureDataPacket`.
19. **Tampering Resistance Test:** Alters the first byte of ciphertext (`data_alterado[0] = 0`), confirming that Poly1305 detects tampering and halts decryption.
20. **PEB Inspection:** Instantiates `Peb`, reads `GS`/`FS`, detects the OS build, and displays critical fields (`ImageBaseAddress`, `BeingDebugged`, `NtGlobalFlag`, etc.).
21. **LDR Traversal:** Iterates `InLoadOrderModuleList` via `ListIter`, displaying loaded DLLs, base addresses, and image sizes.
22. **NTDLL Export Parsing:** Parses `ntdll.dll`'s export table and resolves `"strcpy"` by hash (`0x097c4468`).
23. **Stdcall Dynamic Invocation:** Suspends thread execution for 3 seconds using `dynamic_stdcall_by_name("NtDelayExecution", ...)`.
24. **Cdecl Dynamic Invocation:** Invokes `"strcpy"` in memory using `dynamic_cdecl_by_name`.
25. **Syscall Comparison:**
    - Executes `direct_syscall_6` with hardcoded SSN (`0x0034`) to pause the thread.
    - Dynamically extracts `NtDelayExecution`'s SSN via `get_dinamic_ssn`.
    - Dispatches `indirect_syscall_6` using the dynamic SSN combined with Call Stack Spoofing, spoofing the call stack with NTDLL `.pdata` frames.

### 2. `src/bin/prueba_call_spoofing.rs`: Specialized Evasion PoC

This binary provides an isolated verification of call stack spoofing:
1. Configures a 60-second negative delay interval (`delay_interval = -(60 * 10_000_000)` in 100-nanosecond units).
2. Dynamically extracts the SSN for `NtDelayExecution` by disassembling `ntdll.dll` machine code.
3. Dispatches `indirect_syscall_6`: synthesizes stack frames for `RtlUserThreadStart` and `BaseThreadInitThunk`, locates ROP gadgets `ADD RSP, 0x38; RET` and `CALL <AnchorReg>`, appends a `0x0` null return address, expands the stack, and jumps to the `syscall` instruction within `ntdll.dll`.
4. The thread enters a 60-second wait state while stack inspection utilities observe a legitimate call stack trace.

---

## Compilation, Optimization, and Laboratory Environments

### Optimization Profile in `Cargo.toml`

The release profile (`[profile.release]`) is tuned to minimize binary footprint and deter static analysis:

```toml
[profile.release]
opt-level = "z"     # Aggressively optimizes for machine code size
lto = true          # Link-Time Optimization across all crates to strip dead code
codegen-units = 1   # Single code generation unit to maximize global LLVM optimizations
panic = "abort"     # Strips panic unwinding tables, significantly reducing binary size
strip = true        # Automatically strips debug symbols and metadata from the final PE
```

### Cross-Compilation for Windows

From Linux environments, cross-compilation is performed using the Windows GNU toolchain:

#### 64-Bit Architecture (x86_64) — *Primary Target*
```bash
cargo build --target x86_64-pc-windows-gnu --bin prueba --release
cargo build --target x86_64-pc-windows-gnu --bin prueba_call_spoofing --release
```

#### 32-Bit Architecture (i686) — *Compatibility Status*
```bash
cargo build --target i686-pc-windows-gnu --bin prueba --release
```

> [!TIP]
> **Note on 32-Bit (`i686`) Compilation Support:**
> Modules `src/structures/pe/` and `src/structures/peb/` contain comprehensive 32-bit (x86) definitions and offset tables. However, the system call dispatchers (`dinamic_ssn.rs` and `indirect_syscall.rs`) are conditionally gated with `#[cfg(target_arch = "x86_64")]` because indirect syscalls with stack spoofing under 32-bit Windows require implementing *Heaven's Gate* in WoW64 environments. Therefore, the fully supported operational target for evasion execution and integration tests is **`x86_64-pc-windows-gnu`**.

### Lab Execution with Wine

For dynamic testing on Linux workstations without requiring a dedicated Windows virtual machine, binaries can be executed within isolated Wine prefixes:

#### 64-Bit Wine Environment Execution
```bash
WINEPREFIX=~/.wine64 WINEARCH=win64 wine target/x86_64-pc-windows-gnu/release/prueba.exe
```

#### Call Stack Spoofing PoC Execution in 64-Bit Wine
```bash
WINEPREFIX=~/.wine64 WINEARCH=win64 wine target/x86_64-pc-windows-gnu/release/prueba_call_spoofing.exe
```

#### 32-Bit Wine Environment Execution
```bash
WINEPREFIX=~/.wine32 WINEARCH=win32 wine target/i686-pc-windows-gnu/release/prueba.exe
```

---

## Summary Matrix of Files and Components

| Submodule | File | Key Functions / Structs | Technical Responsibility |
|---|---|---|---|
| **Root** | `src/lib.rs` | Public module declarations | Crate modular structure |
| **Utilities** | `src/utils.rs` | `read_u8`, `read_u16`, `read_u32`, `read_ptr`, `UnicodeString` | Unaligned memory access and UTF-16 to UTF-8 conversion |
| **NT Types** | `src/nt/types.rs` | `HANDLE`, `LARGE_INTEGER`, `STATUS_INFO_LENGTH_MISMATCH` | Native NT kernel primitive type definitions |
| **NT Process** | `src/nt/process/open_process.rs` | `open_process`, `DESIRED_ACCESS`, `CLIENT_ID`, `OBJECT_ATTRIBUTES` | Native process opening via `NtOpenProcess` (0xaddc1c2e) |
| **NT Process** | `src/nt/process/query_information_process.rs` | `query_information_process`, `print_all_handles_info` | Handle enumeration via `NtQueryInformationProcess` (0x6fa0c1f4) |
| **Kernel Objects** | `src/nt/kernel_objects/close.rs` | `nt_close` | Kernel handle teardown via `NtClose` (0x1c0fcdc4) |
| **Kernel Objects** | `src/nt/kernel_objects/duplicate_object.rs` | Commented placeholder | Planned stub for `NtDuplicateObject` |
| **Kernel Objects** | `src/nt/kernel_objects/query_object.rs` | `query_object_find_struct_size`, `query_object_size_solved` | Dynamic object inspection via `NtQueryObject` (0xfc2a599c) |
| **NT Memory** | `src/nt/memory/virtual_alloc.rs` | `nt_allocate_virtual_memory`, `AllocationType`, `PageProtection` | Memory allocation via `NtAllocateVirtualMemory` (0x2759addf) |
| **NT Memory** | `src/nt/memory/read_process_mem.rs` | `nt_read_virtual_memory` | Remote memory read via `NtReadVirtualMemory` (0x7a58c6ca) |
| **NT Memory** | `src/nt/memory/write_process_mem.rs` | `nt_write_virtual_memory` | Remote memory write via `NtWriteVirtualMemory` (0x7f603ee9) |
| **NT Memory** | `src/nt/memory/protect_virtual_mem.rs` | `nt_protect_virtual_memory`, `MemoryProtection` | Page protection changes via `NtProtectVirtualMemory` (0x96e11bf8) |
| **NT Memory** | `src/nt/memory/query_virtual_mem.rs` | `nt_query_virtual_memory`, `escanear_memoria_proceso` | Page query (`MEMORY_BASIC_INFORMATION`) and visual memory map |
| **NT Memory** | `src/nt/memory/pattern_scan_mem.rs` | `mem_remote_pattern_find`, `pdata_pattern_find_starting_at_rand_func` | Byte scanning, `.pdata` boundaries, and randomized search with `OsRng` |
| **PE Parser** | `src/structures/pe/constants.rs` | `DOS_E_LFANEW`, `PE_SIGNATURE`, `PE32_PLUS_MAGIC` | Portable Executable constants and magic numbers |
| **PE Parser** | `src/structures/pe/headers.rs` | `PeHeaderInfo::parse_headers` | Manual parsing of DOS and NT headers |
| **PE Parser** | `src/structures/pe/optional_header.rs` | `ImageOptionalHeader64`, `ImageDataDirectory` | Optional header analysis and memory alignment checks |
| **PE Parser** | `src/structures/pe/export.rs` | `ExportTable::new`, `ExportEntry` | Export table parsing and Forwarded Export (`[fwd]`) detection |
| **PE Parser** | `src/structures/pe/helpers.rs` | `read_cstr` | Null-terminated ASCII string reader |
| **PEB / TEB** | `src/structures/peb/peb.rs` | `Peb::get_ptr`, `detect_version` | PEB retrieval (`GS:[0x60]` / `FS:[0x30]`) and OS build classification |
| **PEB Loader** | `src/structures/peb/ldr.rs` | `PebLdrData`, `_PEB_LDR_DATA` | Dynamic loader structures for x64 and x86 |
| **PEB Loader** | `src/structures/peb/ldr_entry.rs` | `LdrDataTableEntry` | Loaded module mapping and historical field evolution (Vista to Win11) |
| **PEB Lists** | `src/structures/peb/list_entry.rs` | `ListEntry`, `containing_record`, `ListIter` | Circular doubly-linked list iteration and `CONTAINING_RECORD` macro |
| **PEB Offsets** | `src/structures/peb/offsets/` | `peb_x64.rs`, `peb_x86.rs` | Exhaustive offset lookup tables by kernel version |
| **Discovery** | `src/techniques/discovery/process.rs` | `process_discovery`, `get_process_table` | Process enumeration via `NtQuerySystemInformation` with table rendering |
| **Evasion Hashing** | `src/techniques/evasion/api_hashing.rs` | `unique_hash` | Modified FNV-1a with ROR-7 and XOR mask for string obfuscation |
| **API Resolution** | `src/techniques/evasion/dinamic_api_resolution.rs` | `get_ntdll_base`, `get_export_by_name_hash` | PEB module discovery and EAT export search without Windows APIs |
| **SSN Opcodes** | `src/techniques/evasion/syscall_opcodes.rs` | Windows 10 x64 SSN constants | Reference catalog for static validation of system services |
| **Dynamic SSN** | `src/techniques/evasion/execution/dinamic_ssn.rs` | `get_dinamic_ssn` | Runtime SSN extraction in NTDLL and hook detection (INT3 / NOP) |
| **Direct Syscalls** | `src/techniques/evasion/execution/direct_syscall.rs` | `direct_syscall_6` | Direct inline assembly invocation (`syscall` / `sysenter`) |
| **Dynamic Invocation** | `src/techniques/evasion/execution/dynamic_call.rs` | `dynamic_stdcall_by_name`, `dynamic_cdecl_by_name` | NTDLL function invocation wrappers by name or hash |
| **Normal Calls** | `src/techniques/evasion/execution/normal_call.rs` | `call_cdecl`, `call_stdcall` | Arity-based call dispatcher (0 to 10 args) adapted for x86 and x64 |
| **Indirect Syscalls** | `src/techniques/evasion/execution/indirect_syscall.rs` | `indirect_syscall_6` | Indirect dispatch to `syscall; ret` gadget in NTDLL with stack spoofing |
| **Synthetic Stack** | `src/techniques/evasion/stack_spoofing/call_stack_spoofing.rs` | `prepare_spoof_data`, `SpoofData` | Synthetic frame assembly with `RtlUserThreadStart`, `BaseThreadInitThunk`, and gadgets |
| **Unwind Info** | `src/techniques/evasion/stack_spoofing/unwind_info.rs` | `get_unwind_offsets`, `parse_pdata_entry` | `.pdata` directory decoding and x64 `UNWIND_INFO` opcode parsing |
| **Evasion Memory** | `src/techniques/evasion/memory/write_process_mem_rw_rx.rs` | `write_process_mem_rw_rx` | Remote memory injection via RW $\rightarrow$ RX transition cycle |
| **Crypto Keys** | `src/cipher/keys.rs` | `Identity`, `SymetricKey` | X25519 key generation and Diffie-Hellman shared secret derivation |
| **Crypto AEAD** | `src/cipher/cipher_data.rs` | `CipherData::cipher`, `CipherData::decipher` | ChaCha20-Poly1305 authenticated encryption and decryption (28B overhead) |
| **Crypto Handshake** | `src/cipher/handshake.rs` | `SecureClientHandshakePacket` | Handshake with client static public key anonymization (92B) |
| **Crypto Session** | `src/cipher/communication.rs` | `SecureDataPacket` | Encrypted message envelope for operational session data |
| **Binary Suite** | `src/bin/prueba.rs` | Sequential 25-step execution | Full end-to-end integration and demonstration suite |
| **Binary Spoofing** | `src/bin/prueba_call_spoofing.rs` | Isolated 60-second PoC | Thread suspension with `NtDelayExecution` via indirect syscall & stack spoofing |
