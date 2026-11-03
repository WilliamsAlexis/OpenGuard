# OpenGuard 🛡️ - Antivirus Defensivo para Windows 10/11 en C++20

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++20](https://img.shields.io/badge/standard-C%2B%2B20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Compiler: MSVC 2022](https://img.shields.io/badge/compiler-MSVC%202022-red.svg)](https://visualstudio.microsoft.com/)
[![Platform: Windows 10/11](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-blue.svg)](https://www.microsoft.com/windows)
[![Architecture: x64](https://img.shields.io/badge/arch-x64-lightgrey.svg)]()

> **Idioma:** [Español](#español) | [English](#english)

---

<a name="español"></a>
## Español

### ¿Qué es OpenGuard?

**OpenGuard** es un antivirus gratuito, de código abierto y de alta eficiencia desarrollado en **C++20** nativo para Windows 10 y 11. Diseñado bajo principios de **ciberseguridad defensiva** y **privacidad por diseño**, OpenGuard realiza todo el análisis criptográfico, heurístico y de comportamiento de forma **100% local**, sin telemetría ni exfiltración de datos hacia servidores externos.

---

### ✨ Características y Métodos Defensivos Implementados

| Módulo | Tecnología Subyacente | Capacidad Defensiva |
|---|---|---|
| **Cotejo de Firmas** | SQLite3 B-Tree + BCrypt | Búsqueda indexada instantánea por SHA-256, SHA-1 y MD5 con lectura en bloques de 64 KB. |
| **Análisis Estático PE** | Estructuras nativas `winnt.h` | Parseo profundo de binarios x86/x64, verificación de puntos de entrada y anomalías de timestamp. |
| **Entropía de Shannon** | Cálculo matemático de entropía | Detección de secciones con entropía $> 7.1$ (indicio crítico de compresión o empaquetado malicioso). |
| **Inspección de Imports (IAT)** | Tabla de Importaciones PE | Detección de combinaciones de APIs de inyección (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`). |
| **Permisos W+X** | Flags de sección PE | Detección de secciones con permisos simultáneos de Escritura y Ejecución (técnica común de unpackers). |
| **Firmas Authenticode** | WinVerifyTrust API | Comprobación de validez criptográfica de firmas digitales y extracción de entidades emisoras. |
| **Heurística de Scripts** | Motor sintáctico multilinguaje | Detección de evasión de AMSI, cunas de descarga (`Net.WebClient`), ejecución en memoria (IEX) y Base64. |
| **Bóveda de Cuarentena** | AES-256 CBC con Windows CNG | Aislamiento cifrado `.qbin` con destrucción segura del archivo original mediante sobrescritura aleatoria. |
| **Auditoría de Vulnerabilidades** | Win32 Registry + NetAPI | Detección de SMBv1 activo (EternalBlue), UAC desactivado, Firewall o Defender deshabilitados y cuenta Guest. |
| **Auditoría de Red** | IP Helper API (iphlpapi) | Enumeración de conexiones TCP/UDP con PID propietario, detección de puertos C2 (4444, 1337) y secuestro de `hosts`. |
| **Servicio de Windows** | Service Control Manager (SCM) | Ejecución en segundo plano (`openguard_service.exe`) con soporte de instalación y remoción desatendida. |

---

### 🏛️ Arquitectura Modular del Proyecto

```
OpenGuard/
├── include/openguard/          # Encabezados públicos C++20
│   ├── types.h                 # Modelos ScanResult, RiskLevel, ThreatInfo
│   ├── crypto_utils.h          # Criptografía nativa Windows CNG (BCrypt)
│   ├── signatures.h            # Gestor SQLite3 de firmas
│   ├── pe_analyzer.h           # Analizador estático PE y Authenticode
│   ├── quarantine.h            # Bóveda cifrada AES-256
│   ├── heuristics.h            # Motor de scripts (PowerShell, VBS, Batch)
│   ├── vuln_scan.h             # Auditor de configuraciones de Windows
│   ├── network_scan.h          # Auditor de sockets TCP/UDP y puertos C2
│   └── thread_pool.h           # Pool de subprocesos concurrente
├── src/
│   ├── core/                   # Biblioteca estática openguard_core
│   ├── cli/                    # Herramienta de línea de comandos openguard_cli
│   └── service/                # Servicio del sistema openguard_service
├── tests/                      # Suite de pruebas unitarias (Google Test)
├── signatures/                 # Firmas JSON, manifest.sha256 y reglas YARA
├── installer.iss               # Script de empaquetado para Inno Setup
└── ROADMAP.md                  # Plan de evolución hacia Minifilter Driver (Kernel Ring 0)
```

---

### 🛠️ Compilación con Visual Studio 2022 y CMake

#### 1. Requisitos Previos
- Windows 10 o 11 (64 bits).
- Visual Studio 2022 (con la carga de trabajo *"Desarrollo para el escritorio con C++"*).
- CMake 3.22 o superior.
- vcpkg instalado en `C:\vcpkg`.

#### 2. Instalación de Dependencias con vcpkg
```powershell
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
cd C:\vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
```

#### 3. Configuración y Compilación
```powershell
cd d:\APLICACIONES\OpenGuard

# Generar la solución de Visual Studio 2022 para x64
cmake -B build -S . -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE="C:/vcpkg/scripts/buildsystems/vcpkg.cmake"

# Compilar en modo Release optimizado
cmake --build build --config Release --parallel
```

Los binarios generados se encontrarán en:
- `build\src\cli\Release\openguard_cli.exe`
- `build\src\service\Release\openguard_service.exe`
- `build\tests\Release\openguard_tests.exe`

#### 4. Ejecución de Pruebas Unitarias
```powershell
ctest --test-dir build -C Release --output-on-failure
```

---

### 🧪 Prueba Defensiva con el Archivo Estándar EICAR

> **AVISO IMPORTANTE**: Nunca ejecutes ni descargues malware real. Realiza siempre tus pruebas de validación en máquinas virtuales (Hyper-V, VirtualBox o VMware) utilizando el archivo de prueba estándar EICAR.

1. Genera el archivo inofensivo EICAR en PowerShell:
   ```powershell
   Set-Content -Path "test_eicar.txt" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' -NoNewline
   ```

2. Ejecuta OpenGuard CLI:
   ```powershell
   .\build\src\cli\Release\openguard_cli.exe scan test_eicar.txt
   ```

3. **Resultado**: OpenGuard identificará la firma `EICAR-Standard-AV-Test-File-Raw`, informará los hashes criptográficos calculados mediante BCrypt y reportará la alerta de severidad correspondiente.

---

### 📦 Empaquetado del Instalador con Inno Setup

Para generar un instalador ejecutable único para distribución:
1. Descarga e instala [Inno Setup](https://jrsoftware.org/isdl.php).
2. Compila el script de empaquetado:
   ```powershell
   & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss
   ```
3. El instalador generado estará disponible en `dist\OpenGuard_Setup_v0.1.0.exe`.

---

### 🚀 Publicación en GitHub (https://github.com/WilliamsAlexis/OpenGuard)

```powershell
cd d:\APLICACIONES\OpenGuard

# 1. Configurar rama principal
git branch -M main

# 2. Configurar el origen remoto
git remote add origin https://github.com/WilliamsAlexis/OpenGuard.git

# 3. Preparar archivos
git add .

# 4. Crear commit de versión C++20
git commit -m "feat(cpp): complete native C++20 defensive antivirus engine with Win32 CNG, PE analyzer and AES-256 vault"

# 5. Subir a GitHub
git push -u origin main

# 6. Crear y subir Tag de versión
git tag -a v0.1.0 -m "OpenGuard v0.1.0 - Native C++20 Release"
git push origin v0.1.0
```

---

<a name="english"></a>
## English

**OpenGuard** is a free and open-source defensive antivirus and security scanner for Windows 10/11 written in modern **C++20** using native Win32 APIs, Windows Cryptography Next Generation (CNG / BCrypt), and SQLite3.

### Core Capabilities
- **C++20 Multithreaded Engine**: High-throughput file scanning via native thread pool with 64 KB chunked reads.
- **PE Static Analyzer**: Section Shannon entropy calculation ($H > 7.1$), W+X permission detection, suspicious IAT imports (`VirtualAllocEx`, `CreateRemoteThread`), and Authenticode verification via `WinVerifyTrust`.
- **Script Heuristics**: Detection of AMSI bypasses, Base64 obfuscated PowerShell, in-memory execution cradles, and ransomware volume shadow copy deletion (`vssadmin`).
- **AES-256 Quarantine Vault**: Hardware-accelerated symmetric encryption with cryptographic DoD secure wipe before original deletion.
- **System Hardening Audit**: Audits SMBv1 (EternalBlue vector), UAC status, Windows Firewall profiles, and RDP exposure.
- **Network Sockets Audit**: Extended TCP table inspection with owning PID resolution and C2 port alerting.

Refer to [`ROADMAP.md`](ROADMAP.md) for technical documentation on user-mode limitations and kernel minifilter driver planning.

