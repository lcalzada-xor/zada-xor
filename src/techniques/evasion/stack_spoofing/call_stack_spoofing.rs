use super::unwind_info::*;
use crate::structures::pe::headers::*;
use crate::structures::pe::optional_header::get_data_directory_entry;
use crate::structures::pe::optional_header::*;
use crate::techniques::evasion::dinamic_api_resolution::get_ntdll_base;

pub fn call_stack_spoofing() {
    let func1 = "RtlUserThreadStart";
    let func2 = "BaseThreadInitThunk";
    let func3 = "NtClose";

    unsafe {
        let ntdll = get_ntdll_base().expect("Failed to get ntdll.dll base address");
        let headers = PeHeaderInfo::parse_headers(ntdll).expect("Failed to get headers");
        let optional_headers = get_optional_header(ntdll).expect("Failed to get optional headers");
        let pdata = get_data_directory_entry(ntdll).expect("Failed to get .pdata");
        let unwind_info = get_unwind_info(ntdll).expect("Failed to get unwind info");
    }
}
