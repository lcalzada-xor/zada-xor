use crate::miscdll::winhttp::win_http_close_handle::win_http_close_handle;
use crate::miscdll::winhttp::win_http_connect::*;
use crate::miscdll::winhttp::win_http_open::*;
use crate::miscdll::winhttp::win_http_open_request::*;
use crate::miscdll::winhttp::win_http_read_data::win_http_read_data;
use crate::miscdll::winhttp::win_http_receive_response::win_http_receive_response;
use crate::miscdll::winhttp::win_http_send_request::*;
use crate::nt::types::*;

/// Convierte un `&str` dinámico a un vector de UTF-16 terminado en nulo (`\0`).
fn to_wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Guarda RAII para garantizar el cierre seguro de cualquier `HINTERNET` al salir del scope.
struct SafeHInternet(HINTERNET);

impl Drop for SafeHInternet {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = win_http_close_handle(self.0);
            self.0 = std::ptr::null_mut();
        }
    }
}

/**
 * Realiza una petición HTTP/HTTPS completa utilizando WinHTTP y devuelve los bytes de la respuesta.
 *
 * # Parámetros
 * - `domain`: Host de destino (p. ej. `"www.google.com"` o `"https://api.github.com"`).
 * - `resource`: Ruta del recurso (p. ej. `"/index.html"` o `"/api/v1/data"`).
 * - `user_agent`: Cabecera User-Agent (p. ej. `"Mozilla/5.0"`).
 * - `method`: Verbo HTTP (`"GET"`, `"POST"`, `"PUT"`, etc.).
 * - `headers`: Opcional lista de tuplas con cabeceras `("Header-Name", "Value")`.
 * - `body`: Opcional buffer de bytes a enviar en el cuerpo de la petición.
 *
 * # Retorno
 * - `Ok(Vec<u8>)` con los bytes de la respuesta recibida.
 * - `Err(String)` con la descripción del fallo si ocurre algún error.
 */
pub fn net_req_and_response(
    domain: &str,
    resource: &str,
    user_agent: &str,
    method: &str,
    headers: Option<&[(&str, &str)]>,
    body: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    // 1. detector https o http y satinizamos el dominio
    let is_https = domain.starts_with("https://");
    let mut clean_domain = domain
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    // si el dominio tiene una barra lo quitamos
    if let Some(idx) = clean_domain.find('/') {
        clean_domain = &clean_domain[..idx];
    }

    // parseamos si se ha puesto un puerto, ej: "example.com:8080"
    let (host, port, is_secure) = if let Some(idx) = clean_domain.find(':') {
        let (h, p_str) = clean_domain.split_at(idx);
        let p = p_str[1..].parse::<u16>().unwrap_or(if is_https { 443 } else { 80 });
        (h, p, is_https || p == 443)
    } else if is_https {
        (clean_domain, INTERNET_DEFAULT_HTTPS_PORT, true)
    } else {
        (clean_domain, INTERNET_DEFAULT_HTTP_PORT, false)
    };

    // 2. parseamos strings
    let w_user_agent = to_wide_str(if user_agent.is_empty() { "Mozilla/5.0" } else { user_agent });
    let w_host = to_wide_str(host);
    let w_resource = to_wide_str(if resource.is_empty() { "/" } else { resource });
    let w_method = to_wide_str(if method.is_empty() { "GET" } else { method });

    // 3. abrimos handle sesion http
    let raw_session = win_http_open(
        w_user_agent.as_ptr(),
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0,
    ).map_err(|e| format!("WinHttpOpen falló: {}", e))?;
    let _session_guard = SafeHInternet(raw_session);

    // 4. creamos handle conexion
    let raw_connection = win_http_connect(
        raw_session,
        w_host.as_ptr(),
        port,
        0,
    ).map_err(|e| format!("WinHttpConnect falló al conectar a {}:{}: {}", host, port, e))?;
    let _conn_guard = SafeHInternet(raw_connection);

    // 5. abrimos handle request
    let open_flags = if is_secure { WINHTTP_FLAG_SECURE } else { 0 };
    let raw_request = win_http_open_request(
        raw_connection,
        w_method.as_ptr(),
        w_resource.as_ptr(),
        std::ptr::null(),
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        open_flags,
    ).map_err(|e| format!("WinHttpOpenRequest falló: {}", e))?;
    let _req_guard = SafeHInternet(raw_request);

    // 6. si hay headers,los parseamos en dos mitades Key:value y los pusheamos al buffer w_headers
    let w_headers = headers.map(|h_list| {
        let mut full_headers = String::new();
        for (k, v) in h_list {
            full_headers.push_str(k);
            full_headers.push_str(": ");
            full_headers.push_str(v);
            full_headers.push_str("\r\n");
        }
        to_wide_str(&full_headers)
    });

    // pillamos el puntero y logitud de los headers
    let (headers_ptr, headers_len) = match w_headers {
        Some(ref h) => (h.as_ptr(), (h.len() - 1) as DWORD), // sin el nulo final
        None => (WINHTTP_NO_ADDITIONAL_HEADERS, 0),
    };

    // 7. si existe body lo pasamos como puntero y logigitud
    let (body_ptr, body_len) = match body {
        Some(b) => (b.as_ptr() as LPVOID, b.len() as DWORD),
        None => (WINHTTP_NO_REQUEST_DATA, 0),
    };

    // 8. enviamos  la petición HTTP (dispara DNS, TCP y TLS)
    win_http_send_request(
        raw_request,
        headers_ptr,
        headers_len,
        body_ptr,
        body_len,
        body_len,
        0,
    ).map_err(|e| format!("WinHttpSendRequest falló: {}", e))?;

    // 9. espera y recibe la respuesta del servidor
    win_http_receive_response(raw_request, std::ptr::null_mut())
        .map_err(|e| format!("WinHttpReceiveResponse falló: {}", e))?;

    // 10. leer todos los datos del cuerpo de la respuesta en chunks
    let mut response_body = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut bytes_read: DWORD = 0;

    loop {
        win_http_read_data(
            raw_request,
            buffer.as_mut_ptr() as LPVOID,
            buffer.len() as DWORD,
            &mut bytes_read as LPDWORD,
        ).map_err(|e| format!("WinHttpReadData falló: {}", e))?;

        if bytes_read == 0 {
            break; // EOF
        }

        response_body.extend_from_slice(&buffer[..bytes_read as usize]);
    }

    // los handles en teoria sse cierran automáticamente al salir del scope gracias a SafeHInternet
    Ok(response_body) //devolvemos response body
}
