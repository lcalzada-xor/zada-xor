pub const DOS_E_LFANEW: usize = 0x3c;

// nt headers
pub const PE_SIGNATURE: u32 = 0x4550;
pub const NT_SIGNATURE_SIZE: usize = 4;
pub const FILE_HEADER_SIZE: usize = 20;
pub const OPTIONAL_HEADER_MAGIC: usize = 0;

pub const PE32_MAGIC: u16 = 0x010b;
pub const PE32_PLUS_MAGIC: u16 = 0x020b;

// Optional Header
pub const DATA_DIR_EXPORT_OFFSET_PE32: usize = 0x60;
pub const DATA_DIR_EXPORT_OFFSET_PE32_PLUS: usize = 0x70;

// exports
pub const EXP_TIME_DATE_STAMP: usize = 0x04;
pub const EXP_NAME_RVA: usize = 0x0c;
pub const EXP_ORDINAL_BASE: usize = 0x10;
pub const EXP_NUM_FUNCTIONS: usize = 0x14;
pub const EXP_NUM_NAMES: usize = 0x18;
pub const EXP_ADDRESS_OF_FUNCTIONS: usize = 0x1c;
pub const EXP_ADDRESS_OF_NAMES: usize = 0x20;
pub const EXP_ADDRESS_OF_NAME_ORDINALS: usize = 0x24;
