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

    if pdata_base_addr % std::mem::align_of::<ImageRuntimeFunctionEntry>() != 0 {
        // comprobamos que este alineado en memoria la addr base de la estructura
        return Err(
            "La dirección base de .pdata no está correctamente alineada de acuerdo a la estructura.",
        );
    }

    let entry_size = std::mem::size_of::<ImageRuntimeFunctionEntry>(); // 12 bytes
    let number_of_entries = pdata_size / entry_size; // numero de entradas que hay en la tabla .pdata

    unsafe {
        let base_ptr = pdata_base_addr as *const ImageRuntimeFunctionEntry;

        for i in 0..number_of_entries {
            // recorremos cada entrada comparandolo con la addr de la funcion a buscar su unwind infor
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
    pub version_and_flags: u8,         // UBYTE:3 (Version) + UBYTE:5 (Flags)
    pub size_of_prolog: u8,            // UBYTE
    pub count_of_unwind_codes: u8,     // UBYTE
    pub frame_register_and_offset: u8, // UBYTE:4 (Register) + UBYTE:4 (Offset)
}

// Flags oficiales definidos en tu documento
pub const UNW_FLAG_EHANDLER: u8 = 0x01;
pub const UNW_FLAG_UHANDLER: u8 = 0x02;
pub const UNW_FLAG_CHAININFO: u8 = 0x04;

impl ImageUnwindInfo {
    /// Extrae la versión (primeros 3 bits)
    pub fn version(&self) -> u8 {
        self.version_and_flags & 0x07
    }

    /// Extrae los flags (siguientes 5 bits)
    pub fn flags(&self) -> u8 {
        self.version_and_flags >> 3
    }

    /// Extrae el Frame Register (primeros 4 bits)
    pub fn frame_register(&self) -> u8 {
        self.frame_register_and_offset & 0x0F
    }

    /// Extrae el Frame Register Offset (siguientes 4 bits) y aplica la escala (* 16)
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
    pub start_address: u32,       // ULONG
    pub end_address: u32,         // ULONG
    pub unwind_info_address: u32, // ULONG
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
