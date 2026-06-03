use crate::structures::pe::constants::*;
use crate::structures::pe::headers::PeHeaderInfo;
use crate::structures::pe::helpers::read_cstr;
use crate::utils::{read_u16, read_u32};

pub struct ExportEntry {
    pub ordinal: u32,
    pub rva: u32,
    pub va: *const u8,
    pub name: Option<String>,
}

pub struct ExportTable {
    pub dll_name: String,
    pub ordinal_base: u32,
    pub time_date_stamp: u32,
    pub entries: Vec<ExportEntry>,
}

impl ExportTable {
    pub unsafe fn new(base: *const u8) -> Option<Self> {
        unsafe {
            let headers = PeHeaderInfo::parse_headers(base)?;
            let opt = headers.optional_header_ptr;

            let exp_dir_off = headers.export_directory_offset()?;

            let exp_rva = read_u32(opt, exp_dir_off) as usize;
            let exp_size = read_u32(opt, exp_dir_off + 4) as usize;
            if exp_rva == 0 || exp_size == 0 {
                return None;
            }

            let exp = base.add(exp_rva);

            let ordinal_base = read_u32(exp, EXP_ORDINAL_BASE);
            let time_date_stamp = read_u32(exp, EXP_TIME_DATE_STAMP);
            let num_functions = read_u32(exp, EXP_NUM_FUNCTIONS) as usize;
            let num_names = read_u32(exp, EXP_NUM_NAMES) as usize;

            let fn_rva_table = base.add(read_u32(exp, EXP_ADDRESS_OF_FUNCTIONS) as usize);
            let name_rva_table = base.add(read_u32(exp, EXP_ADDRESS_OF_NAMES) as usize);
            let ord_table = base.add(read_u32(exp, EXP_ADDRESS_OF_NAME_ORDINALS) as usize);

            let dll_name_rva = read_u32(exp, EXP_NAME_RVA) as usize;
            let dll_name = read_cstr(base.add(dll_name_rva));

            let mut name_map: Vec<Option<String>> = vec![None; num_functions];
            for i in 0..num_names {
                let name_rva = read_u32(name_rva_table, i * 4) as usize;
                let name = read_cstr(base.add(name_rva));
                let ord_idx = read_u16(ord_table, i * 2) as usize;
                if ord_idx < num_functions {
                    name_map[ord_idx] = Some(name);
                }
            }

            let export_range = exp_rva..exp_rva + exp_size;
            let mut entries = Vec::with_capacity(num_functions);

            for i in 0..num_functions {
                let rva = read_u32(fn_rva_table, i * 4);
                if rva == 0 {
                    continue;
                }

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

    pub fn dll_name(&self) -> &str {
        &self.dll_name
    }

    pub fn ordinal_base(&self) -> u32 {
        self.ordinal_base
    }

    pub fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp
    }

    pub fn entries(&self) -> &[ExportEntry] {
        &self.entries
    }

    pub fn into_entries(self) -> Vec<ExportEntry> {
        self.entries
    }
}
