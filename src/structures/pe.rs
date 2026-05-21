use super::utils::*;

// PE header offsets — identical across x86 and x64 for the DOS/NT headers.
// Only the Optional Header differs in size (PE32 vs PE32+).
//
// DOS header
const DOS_E_LFANEW: usize = 0x3c; // RVA to IMAGE_NT_HEADERS

// NT headers (after the PE signature)
const NT_SIGNATURE_SIZE: usize = 4; // "PE\0\0"
const FILE_HEADER_SIZE: usize = 20;
const OPTIONAL_HEADER_MAGIC: usize = 0; // offset inside Optional Header

const PE32_MAGIC: u16 = 0x010b;
const PE32_PLUS_MAGIC: u16 = 0x020b;

// Optional Header — data directory index for exports
const DATA_DIR_EXPORT_OFFSET_PE32: usize = 0x60; // offset inside Optional Header
const DATA_DIR_EXPORT_OFFSET_PE32_PLUS: usize = 0x70;

// IMAGE_EXPORT_DIRECTORY field offsets
const EXP_TIME_DATE_STAMP: usize = 0x04; // ULONG
const EXP_NAME_RVA: usize = 0x0c; // ULONG — RVA to DLL name string
const EXP_ORDINAL_BASE: usize = 0x10; // ULONG
const EXP_NUM_FUNCTIONS: usize = 0x14; // ULONG — entries in AddressOfFunctions
const EXP_NUM_NAMES: usize = 0x18; // ULONG — entries in AddressOfNames
const EXP_ADDRESS_OF_FUNCTIONS: usize = 0x1c; // ULONG (RVA to RVA array)
const EXP_ADDRESS_OF_NAMES: usize = 0x20; // ULONG (RVA to RVA array)
const EXP_ADDRESS_OF_NAME_ORDINALS: usize = 0x24; // ULONG (RVA to USHORT array)

/// One resolved export entry.
pub struct ExportEntry {
    pub ordinal: u32,
    pub rva: u32,
    pub va: *const u8,
    /// `None` for exports-by-ordinal-only.
    pub name: Option<String>,
}

/// Parsed view of a loaded PE's Export Address Table.
pub struct ExportTable {
    pub dll_name: String,
    pub ordinal_base: u32,
    pub time_date_stamp: u32,
    pub entries: Vec<ExportEntry>,
}

impl ExportTable {
    /// Parses the EAT of the PE image mapped at `base`.
    ///
    /// # Safety
    /// `base` must point to a valid, fully-mapped PE image in memory.
    pub unsafe fn new(base: *const u8) -> Option<Self> {
        unsafe {
            // 1. Locate IMAGE_NT_HEADERS
            let e_lfanew = read_u32(base, DOS_E_LFANEW) as usize;
            let nt = base.add(e_lfanew);

            // Verify PE signature
            if read_u32(nt, 0) != 0x4550 {
                return None;
            }

            let opt = nt.add(NT_SIGNATURE_SIZE + FILE_HEADER_SIZE);
            let magic = read_u16(opt, OPTIONAL_HEADER_MAGIC);

            // 2. Find export data directory RVA + size
            let exp_dir_off = match magic {
                PE32_MAGIC => DATA_DIR_EXPORT_OFFSET_PE32,
                PE32_PLUS_MAGIC => DATA_DIR_EXPORT_OFFSET_PE32_PLUS,
                _ => return None,
            };

            let exp_rva = read_u32(opt, exp_dir_off) as usize;
            let exp_size = read_u32(opt, exp_dir_off + 4) as usize;
            if exp_rva == 0 || exp_size == 0 {
                return None; // no exports
            }

            // 3. IMAGE_EXPORT_DIRECTORY
            let exp = base.add(exp_rva);

            let ordinal_base = read_u32(exp, EXP_ORDINAL_BASE);
            let time_date_stamp = read_u32(exp, EXP_TIME_DATE_STAMP);
            let num_functions = read_u32(exp, EXP_NUM_FUNCTIONS) as usize;
            let num_names = read_u32(exp, EXP_NUM_NAMES) as usize;

            let fn_rva_table = base.add(read_u32(exp, EXP_ADDRESS_OF_FUNCTIONS) as usize);
            let name_rva_table = base.add(read_u32(exp, EXP_ADDRESS_OF_NAMES) as usize);
            let ord_table = base.add(read_u32(exp, EXP_ADDRESS_OF_NAME_ORDINALS) as usize);

            // DLL name from the export dir
            let dll_name_rva = read_u32(exp, EXP_NAME_RVA) as usize;
            let dll_name = read_cstr(base.add(dll_name_rva));

            // 4. Build a name lookup: ordinal-index → name
            let mut name_map: Vec<Option<String>> = vec![None; num_functions];
            for i in 0..num_names {
                let name_rva = read_u32(name_rva_table, i * 4) as usize;
                let name = read_cstr(base.add(name_rva));
                let ord_idx = read_u16(ord_table, i * 2) as usize;
                if ord_idx < num_functions {
                    name_map[ord_idx] = Some(name);
                }
            }

            // 5. Walk AddressOfFunctions
            let export_range = exp_rva..exp_rva + exp_size;
            let mut entries = Vec::with_capacity(num_functions);

            for i in 0..num_functions {
                let rva = read_u32(fn_rva_table, i * 4);
                if rva == 0 {
                    continue; // gap in the ordinal table
                }

                // Forwarded export — RVA falls inside the export directory itself.
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

                entries.push(ExportEntry {
                    ordinal: ordinal_base + i as u32,
                    rva,
                    va: base.add(rva as usize),
                    name: name_map[i].clone(),
                });
            }

            Some(Self {
                dll_name,
                ordinal_base,
                time_date_stamp,
                entries,
            })
        }
    }
    // 5. Getters estándar de Rust (sin el prefijo "get_")

    pub fn dll_name(&self) -> &str {
        &self.dll_name
    }

    pub fn ordinal_base(&self) -> u32 {
        self.ordinal_base
    }

    pub fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp
    }

    /// Returns a slice of the export entries.
    pub fn entries(&self) -> &[ExportEntry] {
        &self.entries
    }

    // 6. Consumidor (Patrón Into) en caso de que alguien quiera extraer los entries
    // sin clonar el Vec completo, destruyendo el ExportTable.
    pub fn into_entries(self) -> Vec<ExportEntry> {
        self.entries
    }
}

// Reads a null-terminated ASCII/UTF-8 string from `ptr`.
unsafe fn read_cstr(ptr: *const u8) -> String {
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = core::slice::from_raw_parts(ptr, len);
        String::from_utf8_lossy(slice).into_owned()
    }
}
