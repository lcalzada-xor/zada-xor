use super::utils::HANDLE;
use crate::techniques::evasion::execution::dinamic_ssn::get_dinamic_ssn;
use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;

use std::ffi::c_void;
use std::ops::BitOr;

/* se implementa la funcion open process para obtener el handle de un proceso*/

#[repr(u32)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub enum DESIRED_ACCESS {
    PROCESS_ALL_ACCESS = 0x0410,
    PROCESS_VM_READ = 0x0010,
    PROCESS_VM_WRITE = 0x0020,
    PROCESS_VM_OPERATION = 0x0008,
    PROCESS_QUERY_INFORMATION = 0x0400,
}

impl BitOr<DESIRED_ACCESS> for DESIRED_ACCESS {
    type Output = u32;

    fn bitor(self, other: DESIRED_ACCESS) -> Self::Output {
        (self as u32) | (other as u32)
    }
}

impl BitOr<DESIRED_ACCESS> for u32 {
    type Output = u32;

    fn bitor(self, other: DESIRED_ACCESS) -> Self::Output {
        self | (other as u32)
    }
}

impl BitOr<u32> for DESIRED_ACCESS {
    type Output = u32;

    fn bitor(self, other: u32) -> Self::Output {
        (self as u32) | other
    }
}

#[repr(C)]
pub struct CLIENT_ID {
    pub unique_process: HANDLE,
    pub unique_thread: HANDLE,
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    //necesitamos esta estructura, ya que si no esta crashearia al llamar aNtOpenProcess
    pub length: u32,
    pub root_directory: HANDLE,
    pub object_name: *mut c_void,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

impl Default for OBJECT_ATTRIBUTES {
    // constructor a vacio
    fn default() -> Self {
        Self {
            length: std::mem::size_of::<Self>() as u32,
            root_directory: std::ptr::null_mut(),
            object_name: std::ptr::null_mut(),
            attributes: 0,
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        }
    }
}

impl OBJECT_ATTRIBUTES {
    pub fn new() -> Self {
        Self::default()
    }
}

pub fn open_process(pid: u32, desired_access: u32) -> Result<HANDLE, String> {
    let mut process_handle: HANDLE = std::ptr::null_mut();

    let client_id = CLIENT_ID {
        unique_process: pid as HANDLE,
        unique_thread: std::ptr::null_mut(),
    };

    let mut object_attributes = OBJECT_ATTRIBUTES::new();

    let ssn = get_dinamic_ssn(0xaddc1c2e)?;

    unsafe {
        let status = indirect_syscall_6(
            0xaddc1c2e,
            ssn,
            &mut process_handle as *mut HANDLE as usize,
            desired_access as usize,
            &mut object_attributes as *mut OBJECT_ATTRIBUTES as usize,
            &client_id as *const CLIENT_ID as usize,
            0,
            0,
        );

        match status {
            Ok(return_value) => match return_value {
                0 => Ok(process_handle),
                _ => Err(String::from("NtOpenProcess falló al obtener el handle")),
            },
            Err(e) => Err(e),
        }
    }
}
