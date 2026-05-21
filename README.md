# Zada-Xor 🛡️

**Zada-Xor** es un proyecto de investigación y aprendizaje escrito en **Rust**, diseñado para profundizar en el funcionamiento interno del sistema operativo Windows (*Windows Internals*), el análisis de memoria y el desarrollo de software con fines de seguridad defensiva.

El objetivo principal es entender a bajo nivel cómo se estructuran y resuelven las APIs del sistema, interactuando directamente con componentes internos del núcleo de usuario de Windows.

---

## ⚠️ Descargo de Responsabilidad y Uso Ético (Disclaimer)

> [!IMPORTANT]
> **Este proyecto tiene fines estrictamente educativos, de investigación académica y de seguridad defensiva.**
> 
> * **Uso Autorizado:** El código y los conceptos demostrados aquí están destinados únicamente a ser utilizados en entornos controlados, laboratorios de investigación y sistemas donde se cuente con la autorización explícita de los propietarios.
> * **Finalidad Defensiva:** Está diseñado para ayudar a investigadores de seguridad, analistas de malware y desarrolladores de soluciones EDR/AV a comprender cómo operan estas técnicas de resolución para poder detectarlas y mitigarlas eficazmente.
> * **Prohibición de Uso Malicioso:** El autor no promueve, apoya ni consiente el uso de este software con fines destructivos, intrusivos o maliciosos. Cualquier uso inadecuado o ilegal de esta herramienta es responsabilidad exclusiva del usuario final.

---

## 🛠️ Tecnologías e Implementaciones (x86_64 y x86)

El proyecto implementa de manera manual y desde cero las siguientes técnicas y estructuras de Windows:

* **Procesamiento de PEB (Process Environment Block):** Lectura directa en memoria de la estructura PEB del proceso actual.
* **Estructuras LDR (Loader):** Recorrido manual de la lista cargadora del sistema (`InLoadOrderModuleList`) para localizar módulos base cargados (como `ntdll.dll` o `kernel32.dll`) sin llamadas a la API de Windows estándar.
* **Parsing del formato PE (Portable Executable):** Análisis manual en memoria de las cabeceras DOS y NT, incluyendo la lectura de la tabla de exportación para localizar funciones específicas.
* **Resolución Dinámica de APIs:** Técnicas alternativas a la IAT (*Import Address Table*) estándar para resolver y llamar a funciones del sistema dinámicamente.
