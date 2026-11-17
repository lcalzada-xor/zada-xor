type BSTR = *mut u16;
use std::ptr;
use std::slice;
use std::ffi::c_void;

//todo esto es una reimplementacion manual del formato de cadenas de texto BSTR de COM de windows, evitamos tener que utilizar la libreia oleaut32.dll para no generar telemetria, y ademas nos permite tener un control total sobre la memoria y el formato de las cadenas de texto

#[repr(C, align(4))]
struct StackBstr<const N: usize> {
    byte_len: u32,
    data: [u16; N], // Incluye el carácter nulo final
}

impl<const N: usize> StackBstr<N> {
    const fn new(utf16_with_null: [u16; N]) -> Self {
        assert!(N > 0, "El array debe incluir al menos el terminador nulo");
        Self {
            byte_len: ((N - 1) * 2) as u32,
            data: utf16_with_null,
        }
    }

    /// Devuelve el puntero BSTR apuntando al primer carácter UTF-16 (después del prefijo u32)
    fn as_bstr(&self) -> BSTR {
        self.data.as_ptr() as BSTR
    }
}

/// 2. SysStringLen.
/// Lee los 4 bytes (u32) inmediatamente anteriores al puntero BSTR y divide entre 2.
unsafe fn bstr_len(bstr: BSTR) -> usize {
    if bstr.is_null() {
        return 0;
    }
    let byte_len_ptr = (bstr as *const u8).wrapping_sub(4) as *const u32;
    let byte_len = unsafe { ptr::read_unaligned(byte_len_ptr) };
    (byte_len / 2) as usize
}

/// SysFreeString para BSTR devueltos por COM (taskschd.dll).
/// El bloque real asignado en el heap empieza 4 bytes antes del puntero BSTR.
unsafe fn bstr_free(bstr: BSTR) {
    if bstr.is_null() {
        return;
    }
    let raw_block = (bstr as *mut u8).wrapping_sub(4) as *mut c_void;
    unsafe { CoTaskMemFree(raw_block) }; //TODO: hay que implementar esta funcion para liberar memoria asignada por COM
}

// --- Ejemplo de uso combinado ---
unsafe fn bstr_to_string_and_free(bstr: BSTR) -> String {
    if bstr.is_null() {
        return String::new();
    }
    let len = unsafe { bstr_len(bstr) };
    let slice = unsafe { slice::from_raw_parts(bstr, len) };
    let result = String::from_utf16_lossy(slice);
    unsafe { bstr_free(bstr) };
    result
}