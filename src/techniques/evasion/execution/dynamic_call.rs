use super::normal_call::{call_cdecl, call_stdcall};
use crate::techniques::evasion::dinamic_api_resolution::{
    get_export_by_name, get_export_by_name_hash, get_ntdll_base,
};

/// Executes a function from `ntdll.dll` using the `stdcall` calling convention, resolved by hash.
pub fn dynamic_stdcall_by_hash(hash: u32, args: &[usize]) -> Result<isize, String> {
    unsafe {
        let base = get_ntdll_base();
        if base.is_null() {
            return Err(String::from("Failed to locate NTDLL base address"));
        }
        let addr = get_export_by_name_hash(base, hash)
            .map_err(|e| format!("Failed to resolve API with hash {:#08x}: {}", hash, e))?;
        Ok(call_stdcall(addr, args))
    }
}

/// Executes a function from `ntdll.dll` using the `stdcall` calling convention, resolved by name.
pub fn dynamic_stdcall_by_name(name: &str, args: &[usize]) -> Result<isize, String> {
    unsafe {
        let base = get_ntdll_base();
        if base.is_null() {
            return Err(String::from("Failed to locate NTDLL base address"));
        }
        let addr = get_export_by_name(base, name)
            .map_err(|e| format!("Failed to resolve API '{}': {}", name, e))?;
        Ok(call_stdcall(addr, args))
    }
}

/// Executes a function from `ntdll.dll` using the `cdecl` calling convention, resolved by hash.
pub fn dynamic_cdecl_by_hash(hash: u32, args: &[usize]) -> Result<isize, String> {
    unsafe {
        let base = get_ntdll_base();
        if base.is_null() {
            return Err(String::from("Failed to locate NTDLL base address"));
        }
        let addr = get_export_by_name_hash(base, hash)
            .map_err(|e| format!("Failed to resolve API with hash {:#08x}: {}", hash, e))?;
        Ok(call_cdecl(addr, args))
    }
}

/// Executes a function from `ntdll.dll` using the `cdecl` calling convention, resolved by name.
pub fn dynamic_cdecl_by_name(name: &str, args: &[usize]) -> Result<isize, String> {
    unsafe {
        let base = get_ntdll_base();
        if base.is_null() {
            return Err(String::from("Failed to locate NTDLL base address"));
        }
        let addr = get_export_by_name(base, name)
            .map_err(|e| format!("Failed to resolve API '{}': {}", name, e))?;
        Ok(call_cdecl(addr, args))
    }
}
