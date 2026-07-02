# Zada-Xor

Zada-Xor es un proyecto de investigación y aprendizaje escrito en Rust, enfocado en el análisis de memoria, el estudio de componentes internos del sistema operativo Windows (Windows Internals), técnicas de evasión avanzadas y la implementación de canales de comunicación seguros a nivel de aplicación.

El objetivo principal es entender a bajo nivel cómo se estructuran y resuelven las APIs del sistema, interactuando directamente con componentes internos del núcleo de usuario de Windows.

---

## Descargo de Responsabilidad y Uso Ético (Disclaimer)

> [!IMPORTANT]
> **Este proyecto tiene fines estrictamente educativos, de investigación académica y de seguridad defensiva.**
> 
> * **Uso Autorizado:** El código y los conceptos demostrados aquí están destinados únicamente a ser utilizados en entornos controlados, laboratorios de investigación y sistemas donde se cuente con la autorización explícita de los propietarios.
> * **Finalidad Defensiva:** Está diseñado para ayudar a investigadores de seguridad, analistas de malware y desarrolladores de soluciones EDR/AV a comprender cómo operan estas técnicas de resolución para poder detectarlas y mitigarlas eficazmente.
> * **Prohibición de Uso Malicioso:** El autor no promueve, apoya ni consiente el uso de este software con fines destructivos, intrusivos o maliciosos. Cualquier uso inadecuado o ilegal de esta herramienta es responsabilidad exclusiva del usuario final.

---

## Caracteristicas y Tecnologias Implementadas

El proyecto implementa de manera manual y desde cero las siguientes técnicas y estructuras de Windows:

### Estructuras y Parsing PE / PEB
* **Procesamiento de PEB (Process Environment Block):** Lectura directa en memoria de la estructura PEB del proceso actual.
* **Estructuras LDR (Loader):** Recorrido manual de la lista cargadora del sistema (InLoadOrderModuleList) para localizar módulos base cargados (como ntdll.dll o kernel32.dll) sin realizar llamadas a las APIs estándar de Windows.
* **Parsing del formato PE (Portable Executable):** Análisis manual en memoria de las cabeceras DOS y NT, incluyendo el parsing de la tabla de exportación para localizar funciones específicas.

### Resolucion Dinamica de APIs y Hashing
* **Resolución Dinámica de APIs:** Técnicas alternativas a la IAT (Import Address Table) estándar para resolver y llamar a funciones del sistema dinámicamente mediante hashes de nombres.
* **Algoritmo de Hashing de APIs:** Implementación personalizada basada en FNV-1a con operaciones de desplazamiento de bits XOR/ROR.

### Obtencion Dinamica de SSN (System Service Numbers)
* **Dynamic SSN:** Extracción en tiempo de ejecución de los SSNs de funciones de ntdll.dll analizando el preámbulo de ensamblador de las APIs de interés (búsqueda de patrones Hell's Gate / Halo's Gate) para evitar la dependencia de tablas estáticas.

### Evasion de EDRs mediante Indirect Syscalls y Call Stack Spoofing
* **Llamadas al Sistema Indirectas (Indirect Syscalls):** Redirección del flujo de ejecución hacia instrucciones syscall legítimas dentro del espacio de memoria de ntdll.dll para evadir ganchos (hooks) en espacio de usuario.
* **Spoofing de la Pila de Llamadas (Call Stack Spoofing):**
  * Localización dinámica de frames legítimos mediante la búsqueda de entradas en la sección de excepciones .pdata y el análisis de la información de desenrollado (Unwind Info).
  * Construcción de una pila falsa que simula tener como origen funciones legítimas de Windows como RtlUserThreadStart o BaseThreadInitThunk, intercalando gadgets ensambladores dinámicos para reordenar la pila y terminándola con un frame nulo para engañar a los analizadores de pila de los EDR.

### Gestion de Memoria Virtual
* **Operaciones de Memoria con Syscalls Indirectas:** Implementación de envolturas sobre llamadas del sistema nativas para el control de la memoria de procesos remotos:
  * NtAllocateVirtualMemory: Asignación y reserva de memoria.
  * NtReadVirtualMemory: Lectura del espacio de direcciones virtual.
  * NtWriteVirtualMemory: Escritura de bytes en memoria remota.
  * NtProtectVirtualMemory: Configuración de permisos de página (PAGE_EXECUTE_READWRITE, etc.).
  * NtClose: Cierre de handles de procesos.

### Descubrimiento de Procesos (Process Discovery)
* **NtQuerySystemInformation:** Consulta y parseo de las estructuras SYSTEM_PROCESS_INFORMATION para listar los procesos del sistema mediante llamadas indirectas.
* **Visualización en Consola:** Formateo ordenado en tablas que muestran PID, PPID, Session ID, Hilos, Handles, memoria Working Set y el nombre del proceso ejecutable.

### Canal de Comunicacion Seguro (Cipher)
* **Handshake con X25519:** Intercambio seguro de claves efímeras utilizando Diffie-Hellman en la curva X25519 para definir secretos compartidos de manera anónima y segura.
* **Cifrado ChaCha20Poly1305:** Mecanismo simétrico AEAD para el cifrado y autenticación de la carga útil enviada, garantizando confidencialidad e integridad contra manipulación o interceptación de paquetes.

---

## Estructura del Proyecto

* **src/bin/prueba.rs:** Demostración global del proyecto. Realiza listado de procesos, apertura, lectura, escritura y asignación de memoria con syscalls indirectas, inspecciona el PEB, analiza ntdll.dll, congela hilos mediante NtDelayExecution y simula la comunicación cifrada con el canal seguro.
* **src/bin/prueba_call_spoofing.rs:** Programa de demostración centrado en el retardo de hilos NtDelayExecution mediante syscalls indirectas con call stack spoofing.
* **src/cipher/:** Componentes criptográficos de enlace, cifrado y claves.
* **src/memory/:** Envolturas y utilidades para interactuar con la memoria virtual de los procesos.
* **src/structures/:** Definición e interpretación manual de las estructuras del sistema PE y PEB.
* **src/techniques/:** Implementación de las técnicas de evasión (api hashing, indirect syscalls, call stack spoofing) y descubrimiento de procesos.

---

## Compilacion y Ejecucion

El archivo Cargo.toml está configurado con optimizaciones agresivas de tamaño y ofuscación de debug para el perfil de lanzamiento:
* Nivel de optimización "z" y LTO completo.
* Eliminación de desenrollados de pánicos (abort) y símbolos de depuración (strip).

### Comandos de Compilacion (Cross-compilation para Windows)

#### Arquitectura de 64 bits (x86_64)
```bash
cargo build --target x86_64-pc-windows-gnu --bin prueba --release
```

#### Arquitectura de 32 bits (x86 / i686)
```bash
cargo build --target i686-pc-windows-gnu --bin prueba --release
```

### Ejecucion en Linux con Wine

#### Arquitectura de 64 bits
```bash
WINEPREFIX=~/.wine64 WINEARCH=win64 wine target/x86_64-pc-windows-gnu/release/prueba.exe
```

#### Arquitectura de 32 bits
```bash
WINEPREFIX=~/.wine32 WINEARCH=win32 wine target/i686-pc-windows-gnu/release/prueba.exe
```
