#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::techniques::evasion::execution::dinamic_ssn::get_dinamic_ssn;
use crate::techniques::evasion::execution::indirect_syscall::indirect_syscall_6;
use std::mem::size_of;
use std::ptr::null_mut;


use crate::nt::types::{
    ACCESS_MASK, BOOLEAN, CHAR, GENERIC_MAPPING, HANDLE, LARGE_INTEGER, PULONG, PVOID, UCHAR,
    ULONG, UNICODE_STRING,
};

//
// Object Information
//

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,         // q: OBJECT_BASIC_INFORMATION
    ObjectNameInformation = 1,          // q: OBJECT_NAME_INFORMATION
    ObjectTypeInformation = 2,          // q: OBJECT_TYPE_INFORMATION
    ObjectTypesInformation = 3,         // q: OBJECT_TYPES_INFORMATION
    ObjectHandleFlagInformation = 4,    // qs: OBJECT_HANDLE_FLAG_INFORMATION
    ObjectSessionInformation = 5, // s: void // change object session // (requires SeTcbPrivilege)
    ObjectSessionObjectInformation = 6, // s: void // change object session // (requires SeTcbPrivilege)
    ObjectSetRefTraceInformation = 7,   // since 25H2
    MaxObjectInfoClass = 8,
}

/**
 * The OBJECT_BASIC_INFORMATION structure contains basic information about an object.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OBJECT_BASIC_INFORMATION {
    pub Attributes: ULONG, // The attributes of the object include whether the object is permanent, can be inherited, and other characteristics.
    pub GrantedAccess: ACCESS_MASK, // Specifies a mask that represents the granted access when the object was created.
    pub HandleCount: ULONG,         // The number of handles that are currently open for the object.
    pub PointerCount: ULONG, // The number of references to the object from both handles and other references, such as those from the system.
    pub PagedPoolCharge: ULONG, // The amount of paged pool memory that the object is using.
    pub NonPagedPoolCharge: ULONG, // The amount of non-paged pool memory that the object is using.
    pub Reserved: [ULONG; 3], // Reserved for future use.
    pub NameInfoSize: ULONG, // The size of the name information for the object.
    pub TypeInfoSize: ULONG, // The size of the type information for the object.
    pub SecurityDescriptorSize: ULONG, // The size of the security descriptor for the object.
    pub CreationTime: LARGE_INTEGER, // The time when a symbolic link was created. Not supported for other types of objects.
}

/**
 * The OBJECT_NAME_INFORMATION structure contains the name, if there is one, of a given object.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OBJECT_NAME_INFORMATION {
    pub Name: UNICODE_STRING, // The object name (when present) includes a NULL-terminator and all path separators "\" in the name.
}

/**
 * The OBJECT_TYPE_INFORMATION structure contains various statistics and properties about an object type.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OBJECT_TYPE_INFORMATION {
    pub TypeName: UNICODE_STRING,
    pub TotalNumberOfObjects: ULONG,
    pub TotalNumberOfHandles: ULONG,
    pub TotalPagedPoolUsage: ULONG,
    pub TotalNonPagedPoolUsage: ULONG,
    pub TotalNamePoolUsage: ULONG,
    pub TotalHandleTableUsage: ULONG,
    pub HighWaterNumberOfObjects: ULONG,
    pub HighWaterNumberOfHandles: ULONG,
    pub HighWaterPagedPoolUsage: ULONG,
    pub HighWaterNonPagedPoolUsage: ULONG,
    pub HighWaterNamePoolUsage: ULONG,
    pub HighWaterHandleTableUsage: ULONG,
    pub InvalidAttributes: ULONG,
    pub GenericMapping: GENERIC_MAPPING,
    pub ValidAccessMask: ULONG,
    pub SecurityRequired: BOOLEAN,
    pub MaintainHandleCount: BOOLEAN,
    pub TypeIndex: UCHAR, // since WINBLUE
    pub ReservedByte: CHAR,
    pub PoolType: ULONG,
    pub DefaultPagedPoolCharge: ULONG,
    pub DefaultNonPagedPoolCharge: ULONG,
}

#[repr(C)]
#[derive(Debug)]
pub struct OBJECT_TYPES_INFORMATION {
    pub NumberOfTypes: ULONG,
    pub TypeInformation: [OBJECT_TYPE_INFORMATION; 1],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OBJECT_HANDLE_FLAG_INFORMATION {
    pub Inherit: BOOLEAN,
    pub ProtectFromClose: BOOLEAN,
}

//https://ntdoc.m417z.com/ntqueryobject

pub fn nt_query_object(
    kernel_handle: HANDLE,
    object_info_class: OBJECT_INFORMATION_CLASS,
    object_information: PVOID,
    object_info_lenght: ULONG,
    return_length: PULONG,
) -> Result<usize, String> {
    let api_hash = 0xfc2a599c;
    let ssn = get_dinamic_ssn(api_hash)?;

    unsafe {
        let status = indirect_syscall_6(
            api_hash,
            ssn,
            kernel_handle as usize,
            object_info_class as usize,
            object_information as usize,
            object_info_lenght as usize,
            return_length as usize,
            0,
            0,
            0
        );

        match status {
            Ok(0) => Ok(0),
            Ok(code) => Err(format!("NtQueryObject devolvió NTSTATUS: {:#X}", code)),
            Err(e) => Err(e),
        }
    }
}

//Antes de procesar la respuesta, necesitamos cerciorarnos del tamaño del object info pedido

pub fn query_object_find_struct_size(
    handle: HANDLE,
    object_info_class: OBJECT_INFORMATION_CLASS,
) -> Result<u32, String> {
    let mut return_length: u32 = 0;
    match nt_query_object(
        handle,
        object_info_class,
        std::ptr::null_mut(),
        0,
        &mut return_length as *mut u32,
    ) {
        Ok(_) => {
            if return_length > 0 {
                Ok(return_length as u32)
            } else {
                Err("NtQueryObject devolvió STATUS_SUCCESS pero el tamaño es 0".to_string())
            }
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            println!("[+] NtQueryObject falló: {}", e);
            if (e.contains("C0000004") || e.contains("C0000023")) && return_length > 0 {
                #[cfg(debug_assertions)]
                println!(
                    "[+] Encontrado el tamaño de object_information: {}",
                    return_length
                );
                Ok(return_length as u32)
            } else {
                Err(e)
            }
        }
    }
}

// se divide en dos partes, una para pedir la size del object info y luego hace la query con el tamaño del buffer adecuado para la respuesta

pub fn query_object_size_solved(
    handle: HANDLE,
    object_info_class: OBJECT_INFORMATION_CLASS,
) -> Result<Vec<u8>, String> {

    let initial_size =  query_object_find_struct_size(handle, object_info_class)?;


    let mut current_size = initial_size;
    const MAX_ATTEMPTS: usize = 20;

    for _ in 0..MAX_ATTEMPTS { // metemos un loop aqui por que a veces initial_size no nos devuelve el size real, por eso como fallback llamamos en loop aumentando el buffer hasta que cuele
        let mut buffer = vec![0u8; current_size as usize];
        let mut return_length: u32 = 0;

        match nt_query_object(
            handle,
            object_info_class,
            buffer.as_mut_ptr() as PVOID,
            buffer.len() as u32,
            &mut return_length as *mut u32,
        ) {
            Ok(_) => {
                if return_length > 0 && (return_length as usize) <= buffer.len() {
                    buffer.truncate(return_length as usize);
                }
                return Ok(buffer);
            }
            Err(e) => {
                if e.contains("C0000004") || e.contains("C0000023") {
                    // Si el kernel especificó un tamaño mayor, lo usamos con margen.
                    // Si devolvió un tamaño menor o igual (por ejemplo, cabecera de 8 bytes), duplicamos el búfer.
                    current_size = if return_length > current_size {
                        return_length + 1024
                    } else {
                        current_size * 2
                    };
                } else {
                    return Err(e);
                }
            }
        }
    }

    Err("Se superó el límite de reintentos para NtQueryObject".to_string())
}

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

//funcion necesaria para encontrar el index de un kernel obj en concreto

pub fn query_kernel_object_index(name: &str) -> Result<u32, String> {
    let bytes = query_object_size_solved(null_mut(), OBJECT_INFORMATION_CLASS::ObjectTypesInformation)
        .map_err(|e| format!("query_object_size_solved falló: {}", e))?;

    let types_kernel_objects = bytes.as_ptr() as *const OBJECT_TYPES_INFORMATION;

    unsafe {
        let number_of_types = (*types_kernel_objects).NumberOfTypes;
        let mut current_entry_ptr = &(*types_kernel_objects).TypeInformation[0] as *const OBJECT_TYPE_INFORMATION;

        for i in 0..number_of_types {
            let entry = &*current_entry_ptr;

            let type_name = if !entry.TypeName.Buffer.is_null() && entry.TypeName.Length > 0 {
                let slice = core::slice::from_raw_parts(
                    entry.TypeName.Buffer,
                    (entry.TypeName.Length as usize) / 2,
                );
                String::from_utf16_lossy(slice)
            } else {
                String::new()
            };

            if type_name.eq_ignore_ascii_case(name) {
                let index = if entry.TypeIndex != 0 {
                    entry.TypeIndex as u32
                } else {
                    i
                };
                return Ok(index);
            }

            let next_addr = (current_entry_ptr as usize)
                + size_of::<OBJECT_TYPE_INFORMATION>()
                + entry.TypeName.MaximumLength as usize;

            current_entry_ptr = align_up(next_addr, size_of::<usize>()) as *const OBJECT_TYPE_INFORMATION;
        }

        Err(format!(
            "query_kernel_object_index no encontró ningún índice válido para el objeto: {}",
            name
        ))
    }
}