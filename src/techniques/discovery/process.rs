use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;
use crate::utils::UnicodeString;
use std::alloc::{Layout, alloc, dealloc};
use std::ffi::c_void;

const SYSTEM_PROCESS_INFORMATION_CLASS: usize = 5;
const NT_QUERY_SYSTEM_INFORMATION_SSN: u32 = 0x0036;
const NT_QUERY_SYSTEM_INFORMATION_HASH: u32 = 0xc3d78064;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SystemProcessInformation {
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub working_set_private_size: u64,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    pub create_time: i64,
    pub user_time: i64,
    pub kernel_time: i64,
    pub image_name: UnicodeString,
    pub base_priority: i32,
    pub unique_process_id: *const c_void,
    pub inherited_from_unique_process_id: *const c_void,
    pub handle_count: u32,
    pub session_id: u32,
    pub unique_process_key: usize,
    pub peak_virtual_size: usize,
    pub virtual_size: usize,
    pub page_fault_count: u32,
    pub peak_working_set_size: usize,
    pub working_set_size: usize,
    pub quota_peak_paged_pool_usage: usize,
    pub quota_paged_pool_usage: usize,
    pub quota_peak_non_paged_pool_usage: usize,
    pub quota_non_paged_pool_usage: usize,
    pub pagefile_usage: usize,
    pub peak_pagefile_usage: usize,
    pub private_page_count: usize,
    pub read_operation_count: i64,
    pub write_operation_count: i64,
    pub other_operation_count: i64,
    pub read_transfer_count: i64,
    pub write_transfer_count: i64,
    pub other_transfer_count: i64,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: usize,
    pub parent_pid: usize,
    pub name: String,
    pub threads_count: u32,
    pub working_set_size: u64,
    pub handle_count: u32,
    pub session_id: u32,
    pub virtual_size: usize,
    pub peak_virtual_size: usize,
    pub peak_working_set_size: usize,
    pub private_page_count: usize,
    pub create_time: i64,
    pub user_time: i64,
    pub kernel_time: i64,
    pub cycle_time: u64,
    pub read_operation_count: i64,
    pub write_operation_count: i64,
    pub other_operation_count: i64,
    pub read_transfer_count: i64,
    pub write_transfer_count: i64,
    pub other_transfer_count: i64,
}

fn indirect_call_nt_query_system_information() -> Result<Vec<u8>, String> {
    let mut return_length: usize = 0;
    let mut status = unsafe {
        indirect_syscall_6(
            NT_QUERY_SYSTEM_INFORMATION_HASH,
            NT_QUERY_SYSTEM_INFORMATION_SSN,
            SYSTEM_PROCESS_INFORMATION_CLASS,
            0,
            0,
            &mut return_length as *mut usize as usize,
            0,
            0,
        )
        .unwrap_or(-1)
    };

    if status as u32 != 0xC0000004 {
        #[cfg(debug_assertions)]
        println!(
            "Se esperaba LENGTH_MISMATCH, pero se obtuvo: 0x{:X}",
            status
        );
        return Err(format!(
            "Se esperaba LENGTH_MISMATCH, pero se obtuvo: 0x{:X}",
            status
        ));
    }

    let buffer_size = return_length as usize + 0x2000; // margen de seguridad
    let layout = Layout::from_size_align(buffer_size, 8).map_err(|e| e.to_string())?;
    let buffer_ptr = unsafe { alloc(layout) };

    if buffer_ptr.is_null() {
        return Err("Error al asignar memoria para el búfer".to_string());
    }
    status = unsafe {
        indirect_syscall_6(
            NT_QUERY_SYSTEM_INFORMATION_HASH,
            NT_QUERY_SYSTEM_INFORMATION_SSN,
            SYSTEM_PROCESS_INFORMATION_CLASS,
            buffer_ptr as usize,
            buffer_size,
            &mut return_length as *mut usize as usize,
            0,
            0,
        )
        .unwrap_or(-1)
    };

    if status != 0 {
        unsafe { dealloc(buffer_ptr, layout) };
        #[cfg(debug_assertions)]
        println!(
            "La segunda llamada de indirect_call_nt_query_system_information falló con status: 0x{:X}",
            status
        );
        return Err(format!(
            "La segunda llamada de indirect_call_nt_query_system_information falló con status: 0x{:X}",
            status
        ));
    }

    let data = unsafe { std::slice::from_raw_parts(buffer_ptr, buffer_size).to_vec() };
    unsafe { dealloc(buffer_ptr, layout) };

    Ok(data)
}

pub fn parse_process_data(buffer: &[u8]) -> Option<Vec<ProcessInfo>> {
    let mut current_offset = 0;
    let mut processes = Vec::new();

    loop {
        if current_offset + std::mem::size_of::<SystemProcessInformation>() > buffer.len() {
            break;
        }

        unsafe {
            let proc_info_ptr =
                buffer.as_ptr().add(current_offset) as *const SystemProcessInformation;
            let proc_info = &*proc_info_ptr;

            let name = proc_info.image_name.to_string();
            let name = if name.is_empty() {
                "System Idle Process".to_string()
            } else {
                name
            };

            processes.push(ProcessInfo {
                pid: proc_info.unique_process_id as usize,
                parent_pid: proc_info.inherited_from_unique_process_id as usize,
                name,
                threads_count: proc_info.number_of_threads,
                working_set_size: proc_info.working_set_private_size,
                handle_count: proc_info.handle_count,
                session_id: proc_info.session_id,
                virtual_size: proc_info.virtual_size,
                peak_virtual_size: proc_info.peak_virtual_size,
                peak_working_set_size: proc_info.peak_working_set_size,
                private_page_count: proc_info.private_page_count,
                create_time: proc_info.create_time,
                user_time: proc_info.user_time,
                kernel_time: proc_info.kernel_time,
                cycle_time: proc_info.cycle_time,
                read_operation_count: proc_info.read_operation_count,
                write_operation_count: proc_info.write_operation_count,
                other_operation_count: proc_info.other_operation_count,
                read_transfer_count: proc_info.read_transfer_count,
                write_transfer_count: proc_info.write_transfer_count,
                other_transfer_count: proc_info.other_transfer_count,
            });

            if proc_info.next_entry_offset == 0 {
                break;
            }

            current_offset += proc_info.next_entry_offset as usize;
        }
    }

    if processes.is_empty() {
        None
    } else {
        Some(processes)
    }
}
pub fn process_discovery() -> Result<Vec<ProcessInfo>, String> {
    let result = indirect_call_nt_query_system_information();
    match result {
        Ok(data) => parse_process_data(&data).ok_or("Error al parsear los datos".to_string()),
        Err(e) => Err(e),
    }
}
