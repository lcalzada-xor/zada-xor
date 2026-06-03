#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[allow(non_camel_case_types)]
pub type IMAGE_DATA_DIRECTORY = ImageDataDirectory;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[allow(non_camel_case_types)]
pub type IMAGE_OPTIONAL_HEADER64 = ImageOptionalHeader64;

pub fn parse_optional_header(
    optional_header_base_addr: usize,
) -> Result<ImageOptionalHeader64, &'static str> {
    if optional_header_base_addr == 0 {
        return Err("La dirección base del Optional Header es nula.");
    }

    if optional_header_base_addr % std::mem::align_of::<ImageOptionalHeader64>() != 0 {
        return Err(
            "La dirección de memoria no está correctamente alineada para ImageOptionalHeader64.",
        );
    }

    unsafe {
        let header_ptr = optional_header_base_addr as *const ImageOptionalHeader64;
        let optional_header = *header_ptr;

        if optional_header.magic != 0x20B {
            return Err(
                "El campo Magic no corresponde a un encabezado PE de 64 bits (debe ser 0x20B).",
            );
        }

        Ok(optional_header)
    }
}

pub fn get_data_directory_entry(
    optional_header: &ImageOptionalHeader64,
    index: usize,
) -> Result<ImageDataDirectory, &'static str> {
    if index >= 16 {
        return Err("Índice fuera de los límites del Data Directory (máximo 15).");
    }

    Ok(optional_header.data_directory[index])
}
