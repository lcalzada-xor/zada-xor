use crate::structures::pe::headers::*;
use crate::structures::pe::optional_header::*;

// TOdo este script parsea el .pdata, unwind info derivada y offsets del tamaño de stack de cada funcion, aburrido de cojones.
//-------------Primera parte, conseguir el entry en pdata-------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ImageRuntimeFunctionEntry {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

#[allow(non_camel_case_types)]
pub type IMAGE_RUNTIME_FUNCTION_ENTRY = ImageRuntimeFunctionEntry;

pub fn parse_pdata_entry(
    pdata_base_addr: usize,
    pdata_size: usize,
    func_addr_rva: u32,
) -> Result<ImageRuntimeFunctionEntry, &'static str> {
    if pdata_base_addr == 0 {
        return Err("La dirección base de la tabla .pdata es nula.");
    }

    let entry_size = std::mem::size_of::<ImageRuntimeFunctionEntry>(); // 12 bytes
    if pdata_size < entry_size {
        return Err("El tamaño del directorio .pdata es menor que una entrada individual.");
    }

    if pdata_base_addr % std::mem::align_of::<ImageRuntimeFunctionEntry>() != 0 {
        // comprobamos que este alineado en memoria la addr base de la estructura
        return Err(
            "La dirección base de .pdata no está correctamente alineada de acuerdo a la estructura.",
        );
    }

    let number_of_entries = pdata_size / entry_size; // numero de entradas que hay en la tabla .pdata

    unsafe {
        let base_ptr = pdata_base_addr as *const ImageRuntimeFunctionEntry;

        for i in 0..number_of_entries {
            // el offset no desborde la región de memoria de .pdata
            let offset = i * entry_size;
            if offset + entry_size > pdata_size {
                return Err("Intento de lectura fuera de los límites de la tabla .pdata.");
            }

            let entry_ptr = base_ptr.add(i);
            let entry = *entry_ptr;

            if func_addr_rva >= entry.begin_address && func_addr_rva < entry.end_address {
                return Ok(entry);
            }
        }
    }

    Err("No se encontró ninguna entrada en .pdata para la dirección de función proporcionada.")
}

//-------------Segunda parte, conseguir unwind info-------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ImageUnwindInfo {
    pub version_and_flags: u8,
    pub size_of_prolog: u8,
    pub count_of_unwind_codes: u8,
    pub frame_register_and_offset: u8,
}
pub const UNW_FLAG_EHANDLER: u8 = 0x08;
pub const UNW_FLAG_UHANDLER: u8 = 0x10;
pub const UNW_FLAG_CHAININFO: u8 = 0x20;

impl ImageUnwindInfo {
    pub fn version(&self) -> u8 {
        self.version_and_flags & 0x07
    }

    pub fn flags(&self) -> u8 {
        self.version_and_flags & 0xF8
    }

    pub fn frame_register(&self) -> u8 {
        self.frame_register_and_offset & 0x0F
    }

    pub fn frame_offset_scaled(&self) -> u32 {
        let raw_offset = self.frame_register_and_offset >> 4;
        (raw_offset as u32) * 16
    }
}

/// Variante (1): Si tiene Exception o Termination Handler
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindExceptionHandlerInfo {
    pub handler_address: u32,
}

/// Variante (2): Si la info está encadenada (Chained Unwind Info)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ChainedUnwindInfo {
    pub start_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}
#[derive(Debug)]
pub enum UnwindExtension {
    None,
    ExceptionHandler(UnwindExceptionHandlerInfo),
    Chained(ChainedUnwindInfo),
}

pub fn parse_full_unwind_info(
    unwind_info_base_addr: usize,
) -> Result<(ImageUnwindInfo, UnwindExtension), &'static str> {
    if unwind_info_base_addr == 0 {
        return Err("Dirección base de UNWIND_INFO nula.");
    }

    unsafe {
        // 1. Parsea la cabecera fija (4 bytes)
        let header_ptr = unwind_info_base_addr as *const ImageUnwindInfo;
        let header = *header_ptr;

        // 2. Calcular dónde termina el array de Unwind Codes.
        let raw_codes = header.count_of_unwind_codes as usize;
        let aligned_codes_count = if raw_codes % 2 != 0 {
            raw_codes + 1
        } else {
            raw_codes
        };

        // Cada Unwind Code ocupa 2 bytes (USHORT)
        let unwind_codes_size_bytes = aligned_codes_count * 2;

        // 3. Establecer el puntero donde empiezan los datos variables adicionales
        // Base + 4 bytes de cabecera + tamaño del array de códigos
        let extension_addr = unwind_info_base_addr + 4 + unwind_codes_size_bytes;

        let flags = header.flags();

        // 4. Determinar qué variante leer según los Flags
        if (flags & UNW_FLAG_CHAININFO) != 0 {
            // Variante (2): Chained Unwind Info
            let chained_ptr = extension_addr as *const ChainedUnwindInfo;
            Ok((header, UnwindExtension::Chained(*chained_ptr)))
        } else if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) != 0 {
            // Variante (1): Exception Handler
            let handler_rva_ptr = extension_addr as *const u32;
            let handler_info = UnwindExceptionHandlerInfo {
                handler_address: *handler_rva_ptr,
            };
            Ok((header, UnwindExtension::ExceptionHandler(handler_info)))
        } else {
            // No tiene datos adicionales
            Ok((header, UnwindExtension::None))
        }
    }
}
//-------------Tercera parte, conseguir unwind offsets-------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct UNWIND_CODE {
    pub code_offset: u8,
    pub unwind_op_and_info: u8,
}

impl UNWIND_CODE {
    pub fn unwind_op(&self) -> u8 {
        self.unwind_op_and_info & 0x0F
    }

    pub fn op_info(&self) -> u8 {
        (self.unwind_op_and_info >> 4) & 0x0F
    }

    pub unsafe fn frame_offset(&self) -> u16 {
        unsafe { *(self as *const UNWIND_CODE as *const u16) }
    }
}

pub fn get_unwind_offsets(
    func_addr: usize,
    dll_base: *const u8,
) -> Result<Option<u32>, Box<dyn std::error::Error>> {
    // --- Procesamiento de dll ---
    let dll_headers = match unsafe { PeHeaderInfo::parse_headers(dll_base) } {
        Some(headers) => headers,
        None => return Err("Failed to get dll headers".into()),
    };
    let dll_opt = match parse_optional_header(dll_headers.optional_header_ptr as usize) {
        Ok(opt) => opt,
        Err(_) => return Err("Failed to parse dll optional header".into()),
    };
    let dll_pdata = match get_data_directory_entry(&dll_opt, 3) {
        Ok(pdata) => pdata,
        Err(_) => return Err("Failed to get dll pdata".into()),
    };

    if dll_pdata.virtual_address == 0 || dll_pdata.size == 0 {
        return Err("dll.dll no contiene un directorio de excepciones (.pdata)".into());
    }
    let dll_pdata_va = dll_base as usize + dll_pdata.virtual_address as usize;

    // --- Calcular RVA de la funcion ---
    let func_rva = (func_addr as usize - dll_base as usize) as u32;

    // --- Buscar cada entrada en la tabla .pdata correspondiente ---
    let pdata_entry_func = parse_pdata_entry(dll_pdata_va, dll_pdata.size as usize, func_rva)?;

    // --- Calcular VAs de los Unwind Info ---
    let mut current_unwind_info_va =
        dll_base as usize + pdata_entry_func.unwind_info_address as usize;
    let mut total_offset_bytes: u32 = 0;

    loop {
        let (unwind_info, extension) = parse_full_unwind_info(current_unwind_info_va)?;

        total_offset_bytes += unsafe {
            match calcular_bytes_frame(current_unwind_info_va, unwind_info.count_of_unwind_codes) {
                Some(bytes) => bytes,
                None => return Ok(None),
            }
        };

        match extension {
            UnwindExtension::Chained(chained_info) => {
                let safe_unwind_rva = chained_info.unwind_info_address & !1;
                current_unwind_info_va = dll_base as usize + safe_unwind_rva as usize;
            }
            _ => {
                break;
            }
        }
    }

    Ok(Some(total_offset_bytes))
}

unsafe fn calcular_bytes_frame(unwind_info_va: usize, count_of_codes: u8) -> Option<u32> {
    if count_of_codes == 0 {
        return Some(8); // O return 8, dependiendo de cómo lo tengas en tu código actual
    }

    let codes_ptr = (unwind_info_va + 4) as *const UNWIND_CODE;
    let codes = unsafe { std::slice::from_raw_parts(codes_ptr, count_of_codes as usize) };

    let mut total_bytes: u32 = 0;
    let mut i = 0;

    while i < codes.len() {
        let code = codes[i];
        let op_code = code.unwind_op();
        let op_info = code.op_info();

        match op_code {
            0 => {
                total_bytes += 8;
                i += 1;
            }
            2 => {
                total_bytes += (op_info as u32 * 8) + 8;
                i += 1;
            }
            1 => {
                if op_info == 0 {
                    if i + 1 < codes.len() {
                        let siguiente_slot = unsafe { *(codes_ptr.add(i + 1) as *const u16) };
                        total_bytes += (siguiente_slot as u32) * 8;
                    }
                    i += 2;
                } else if op_info == 1 {
                    if i + 2 < codes.len() {
                        let low = unsafe { *(codes_ptr.add(i + 1) as *const u16) } as u32;
                        let high = unsafe { *(codes_ptr.add(i + 2) as *const u16) } as u32;
                        let siguiente_dword = low | (high << 16);
                        total_bytes += siguiente_dword;
                    } else {
                    }
                    i += 3;
                }
            }
            4 | 8 => {
                i += 2;
            }
            5 | 9 => {
                i += 3;
            }
            3 => {
                return None;
            }
            10 => {
                total_bytes += if op_info == 0 { 40 } else { 48 };
                i += 1;
            }
            _ => {
                return None;
            }
        }
    }
    Some(total_bytes) // O total_bytes + 8, según lo que tengas
}
pub fn get_pdata_of_func_by_rva(
    func_rva: u32,
    dll_base: *const u8,
) -> Result<ImageRuntimeFunctionEntry, Box<dyn std::error::Error>> {
    // --- Procesamiento de dll ---
    let dll_headers = match unsafe { PeHeaderInfo::parse_headers(dll_base) } {
        Some(headers) => headers,
        None => return Err("Failed to get dll headers".into()),
    };
    let dll_opt = match parse_optional_header(dll_headers.optional_header_ptr as usize) {
        Ok(opt) => opt,
        Err(_) => return Err("Failed to parse dll optional header".into()),
    };
    let dll_pdata = match get_data_directory_entry(&dll_opt, 3) {
        Ok(pdata) => pdata,
        Err(_) => return Err("Failed to get dll pdata".into()),
    };



    if dll_pdata.virtual_address == 0 || dll_pdata.size == 0 {
        return Err("dll.dll no contiene un directorio de excepciones (.pdata)".into());
    }
    let dll_pdata_va = dll_base as usize + dll_pdata.virtual_address as usize;

    // --- Calcular RVA de la funcion ---

    // --- Buscar cada entrada en la tabla .pdata correspondiente ---
    let pdata_entry_func = parse_pdata_entry(dll_pdata_va, dll_pdata.size as usize, func_rva)?;

    Ok(pdata_entry_func)
}
pub fn get_pdata_array(dll_base: *const u8) -> Option<Vec<ImageRuntimeFunctionEntry>> {
    let dll_headers = match unsafe { PeHeaderInfo::parse_headers(dll_base) } {
        Some(h) => h,
        None => return None,
    };
    let dll_opt = match parse_optional_header(dll_headers.optional_header_ptr as usize) {
        Ok(opt) => opt,
        Err(_) => return None,
    };
    let dll_pdata = match get_data_directory_entry(&dll_opt, 3) {
        Ok(pdata) => pdata,
        Err(_) => return None,
    };

    if dll_pdata.virtual_address == 0 || dll_pdata.size == 0 {
        return None;
    }

    let pdata_base_addr = (dll_base as usize + dll_pdata.virtual_address as usize)
        as *const ImageRuntimeFunctionEntry;

    let entry_size = std::mem::size_of::<ImageRuntimeFunctionEntry>();
    let num_entries = dll_pdata.size as usize / entry_size;

    unsafe {
        let entries_slice = std::slice::from_raw_parts(pdata_base_addr, num_entries);
        Some(entries_slice.to_vec())
    }
}
