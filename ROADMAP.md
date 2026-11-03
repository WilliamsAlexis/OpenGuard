# OpenGuard 🛡️ - Hoja de Ruta y Arquitectura Futura (ROADMAP)

Este documento detalla la planificación estratégica, las limitaciones intrínsecas de las arquitecturas de seguridad en **Modo Usuario (Ring 3)** y los pasos de ingeniería defensiva necesarios para evolucionar **OpenGuard** hacia una protección robusta a nivel de **Núcleo (Ring 0)** e interfaces avanzadas del sistema operativo Windows 10 y 11.

---

## 1. Alcance de la Versión 1.0 (Modo Usuario)

En su versión 1.0, OpenGuard opera íntegramente en espacio de usuario (*User Mode* / Ring 3) mediante las APIs nativas de Win32, Windows CNG (Cryptography Next Generation) y un servicio de Windows dedicado:

| Componente | Nivel de Ejecución | Rol Defensivo |
|---|---|---|
| **`openguard_core`** | Biblioteca Estática C++20 | Motor de cálculo de hashes (SHA-256/SHA-1/MD5), cotejo en SQLite3 indexado, motor de heurística PE y reglas YARA. |
| **`openguard_service`** | Servicio Win32 (`SYSTEM` / `LocalSystem`) | Monitoreo del sistema de archivos (`ReadDirectoryChangesW`), vigilancia de señuelos anti-ransomware (*honeypots*), escaneo de unidades USB y auditorías periódicas. |
| **`openguard_cli`** | Ejecutable de Usuario / Administrador | Escaneos bajo demanda, automatizaciones, scripts defensivos y pruebas forenses. |
| **`openguard_gui`** | Interfaz Gráfica (Qt6 / ImGui) | Tablero visual de control, gestión de bóveda de cuarentena cifrada (AES-256) y reportes de seguridad. |

---

## 2. Análisis Honesto de Limitaciones en Modo Usuario (Ring 3)

Un antivirus que opera exclusivamente en Ring 3 posee limitaciones técnicas insoslayables frente a atacantes avanzados:

1. **Riesgo de Evasión por Malware con Privilegios Administrativos**:
   - Si un proceso malicioso obtiene privilegios `SeDebugPrivilege` o se ejecuta como `NT AUTHORITY\SYSTEM`, puede terminar el proceso de OpenGuard o suspender sus hilos.
2. **Ceguera ante *Direct System Calls* y *Unhooking***:
   - Los EDRs y antivirus de modo usuario que usan *API Hooking* en `ntdll.dll` pueden ser evadidos por malware que restaura la sección `.text` de `ntdll` o ejecuta directamente instrucciones `syscall`.
3. **Ausencia de Interceptación Pre-Ejecución Obligatoria**:
   - En Ring 3, `ReadDirectoryChangesW` notifica **después** de que un archivo fue creado o modificado en disco (*Post-Operation*). No puede impedir que un ransomware comience a escribir antes de que el evento sea procesado por la cola de mensajes.
4. **Rootkits y Bootkits de Kernel**:
   - Malware que carga un driver vulnerable (*BYOVD - Bring Your Own Vulnerable Driver*) o modifica las tablas internas del kernel (como desvincular un proceso de la lista doblemente enlazada `ActiveProcessLinks` en `EPROCESS`) es completamente invisible para herramientas que consultan `CreateToolhelp32Snapshot` o `EnumProcesses`.

---

## 3. Plan de Evolución hacia Modo Kernel (Ring 0): Driver Minifilter

Para alcanzar paridad con soluciones comerciales de grado empresarial (Windows Defender, CrowdStrike, SentinelOne), la evolución crítica es un **Controlador de Filtro de Sistema de Archivos (*File System Minifilter Driver*)**.

```
                        ┌─────────────────────────────────────┐
                        │      Espacio de Usuario (Ring 3)    │
                        │    OpenGuard Service & Core Engine   │
                        └──────────────────┬──────────────────┘
                                           │ FilterSendMessage
                                           ▼ (Comunicación bidireccional)
                        ┌─────────────────────────────────────┐
                        │      Espacio de Kernel (Ring 0)     │
                        │     OpenGuard.sys (Minifilter)      │
                        │        [FltRegisterFilter]          │
                        └──────────────────┬──────────────────┘
                                           │
         ┌─────────────────────────────────┼─────────────────────────────────┐
         ▼                                 ▼                                 ▼
   [IRP_MJ_CREATE]                   [IRP_MJ_WRITE]                  [IRP_MJ_SET_INFO]
(Intercepta antes de abrir)      (Bloquea ráfagas de cifrado)    (Impide renombrado masivo)
```

### Arquitectura Técnica del Minifilter:
1. **Punto de Entrada**: Registro mediante `FltRegisterFilter` con una estructura `FLT_REGISTRATION`.
2. **Operaciones Clave Interceptadas**:
   - `IRP_MJ_CREATE` (*Pre-Operation Callback*): Intercepta la apertura o ejecución de binarios antes de que el kernel asigne memoria o permita lectura. Si el archivo no ha sido evaluado, el driver pausa la I/O, solicita análisis al servicio en Ring 3 vía `FltSendMessage`, y si es malicioso, completa la IRP con `STATUS_ACCESS_DENIED`.
   - `IRP_MJ_WRITE` (*Pre-Operation Callback*): Vigila la tasa de escritura de procesos sobre extensiones sensibles (.docx, .pdf, .xlsx). Bloquea instantáneamente procesos no autorizados que intenten cifrar archivos.
   - `IRP_MJ_SET_INFORMATION` (*Pre-Operation Callback*): Evita el renombrado masivo de archivos (técnica universal de ransomware que añade extensiones como `.locked`, `.enc`).

### Requisitos de Despliegue en Windows 10/11:
- **Firma Digital WHQL (*Windows Hardware Quality Labs*)**: Windows 10 y 11 exigen obligatoriamente que todo driver en modo kernel esté firmado por Microsoft mediante un certificado EV (*Extended Validation*) a través del portal de desarrollo de hardware de Microsoft (*Partner Center*).
- **Entorno de Pruebas de Desarrollo**: Durante la fase de investigación, se prueba en máquinas virtuales con modo de pruebas activado (`bcdedit /set testsigning on`).

---

## 4. Integraciones Defensivas Adicionales (Roadmap v1.5 - v2.0)

### A. AMSI (*Antimalware Scan Interface*)
- **Rol**: Inspeccionar scripts de PowerShell ofuscados, macros de Office, VBScript y JScript en el momento exacto en que son descifrados en memoria RAM antes de su ejecución.
- **Implementación**: Registrar un proveedor AMSI implementando la interfaz COM `IAmsiStream` y exportando `AmsiInitialize` y `AmsiScanBuffer`.

### B. ETW Ti (*Event Tracing for Windows Threat Intelligence*)
- **Rol**: Proveer telemetría profunda generada directamente por el kernel de Windows para detectar:
  - Inyección de código (`VirtualAllocEx` / `WriteProcessMemory` remotos).
  - Suspensión y manipulación de hilos (`NtQueueApcThread`).
  - Carga de drivers y modificaciones en la memoria de procesos críticos (`lsass.exe`).

### C. ELAM (*Early Launch Anti-Malware*)
- **Rol**: Driver de inicialización temprana clasificado por el cargador de arranque de Windows (*Winload*) que se ejecuta antes que los drivers de terceros para verificar la integridad de todos los módulos que arrancan con el sistema operativo.

### D. Bóveda de Cuarentena con Metadatos Criptográficos
- Uso de AES-256-GCM para garantizar tanto confidencialidad como integridad autenticada de los archivos infectados aislados, previniendo cualquier ejecución involuntaria.

