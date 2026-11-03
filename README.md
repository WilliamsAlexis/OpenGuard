<p align="center"><img src="assets/logo.png" width="120" alt="OpenGuard"></p>

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

**OpenGuard** es un antivirus gratuito y de código abierto desarrollado en **C++20** nativo para Windows 10 y 11. Diseñado bajo principios de **ciberseguridad defensiva** y **privacidad por diseño**, realiza todo el análisis criptográfico, heurístico y de comportamiento de forma **100% local**, sin telemetría ni exfiltración de datos.

> **Estado del proyecto (v0.2):** motor funcional en modo usuario (CLI + servicio de protección en tiempo real). La base de firmas incluida contiene únicamente las firmas del archivo de prueba EICAR: para detectar malware real debe cargar sus propias firmas con `openguard_cli update <archivo.json>`. No sustituye a una solución antivirus comercial; ver [ROADMAP.md](ROADMAP.md) para las limitaciones del modo usuario.

---

### ✨ Características

| Módulo | Tecnología | Capacidad defensiva |
|---|---|---|
| **Cotejo de firmas** | SQLite3 + BCrypt (CNG) | Búsqueda indexada por SHA-256, SHA-1 y MD5 calculados en una sola pasada. Importación masiva desde JSON (`hashes_index.json`). |
| **Análisis estático PE** | Parseo nativo de `winnt.h` | Encabezados PE32/PE32+, **tabla de importaciones (IAT) real**, entropía de Shannon por sección, secciones W+X, punto de entrada anómalo, packers conocidos y overlay. |
| **Combinaciones de APIs** | IAT | Puntúa patrones característicos (inyección remota, process hollowing, keylogger, downloader), no APIs aisladas, para limitar falsos positivos. |
| **Firmas Authenticode** | WinVerifyTrust + catálogos | Valida firmas embebidas **y firmas por catálogo** (binarios de Windows) y extrae el firmante. |
| **Heurística de scripts** | Análisis sintáctico | PowerShell, VBScript/JScript, Batch y HTA: evasión de AMSI, cunas de descarga, IEX, Base64, `vssadmin delete shadows`. |
| **Macros de Office** | Análisis estático | Detecta proyectos VBA en `.doc/.xls/.ppt` (OLE) y `.docm/.xlsm/...` (OOXML), disparadores automáticos (AutoOpen, Document_Open) y llamadas sospechosas; marca como camuflaje un `.docx` con macros. Limitación: el código VBA va comprimido, así que el contenido se ve de forma parcial; la presencia de macros sí es fiable. |
| **Ubicación sospechosa** | Heurística débil | Suma puntos a ejecutables y scripts en Temp, AppData\Roaming, Papelera, Public o Descargas; por sí sola nunca llega al umbral de amenaza. |
| **Programación y progreso** | Servicio + GUI | Análisis rápido o completo programado (diario/semanal, con puesta al día si el equipo estaba apagado) y barra de progreso con total real en análisis rápido y de carpeta (el completo avanza en streaming). |
| **Bóveda de cuarentena** | AES-256-CBC (CNG) + DPAPI | Cifrado `.qbin`, clave protegida con DPAPI, verificación de integridad SHA-256 al restaurar y borrado seguro del original. |
| **Protección en tiempo real** | `ReadDirectoryChangesW` | Servicio de Windows que vigila Descargas, Escritorio, Documentos y Temp, analiza cada archivo nuevo/modificado y escanea USB al conectarse. |
| **Anti-ransomware** | Archivos señuelo + ráfagas | El servicio crea archivos señuelo ocultos en Documentos y Escritorio y alerta si se modifican, eliminan o renombran; también alerta ante >=150 archivos modificados en 10 s. Solo alerta (en modo usuario no puede identificar ni detener el proceso). |
| **Reglas YARA** | Intérprete `yara_lite` | Evalúa `signatures/yara_rules/*.yar` (primeros 4 MB de cada archivo) y reporta detecciones `YARA.<regla>`. |
| **Interfaz gráfica** | Win32 nativo | `openguard_gui.exe`: panel tipo suite comercial con Inicio (estado de protección), Análisis, Actualización, Cuarentena, Informes y Configuración; avisos en la bandeja del sistema. Se ejecuta como Administrador. Avisa cuando hay una nueva versión publicada en GitHub (Releases) y permite descargarla e instalarla con verificación SHA-256. |
| **Auditoría de vulnerabilidades** | Registro + NetAPI | SMBv1, UAC, Firewall, Defender deshabilitado por política, RDP y cuenta Guest. |
| **Auditoría de red** | IP Helper API | Conexiones TCP con PID/proceso, puertos C2 conocidos, secuestro del archivo `hosts` y proxy local. |

**Limitaciones conocidas**

- **Análisis aislado** (servicio y análisis manuales de la GUI): el contenido de cada archivo se analiza en `openguard_worker.exe`, un proceso aparte que recibe el archivo como handle de solo lectura y se protege en capas:
  - token restringido sin privilegios y con el grupo Administradores deshabilitado, e integridad **baja** (se aplica desde el servicio; además el propio worker se baja a integridad baja y se quita todos los privilegios al arrancar, así que también queda protegido si el servicio no pudo crear el token);
  - mitigación del proceso: sin creación de procesos hijos;
  - Job Object con límite de memoria (1 GB), un único proceso, sin UI y tiempo máximo por archivo;
  - **sin red**: el servicio (y el instalador) crean reglas del Firewall de Windows que bloquean todo el tráfico entrante y saliente del worker, de modo que un archivo que lograra explotarlo no puede exfiltrar datos ni descargar código. El estado se ve en Inicio > "Análisis aislado";
  - la salida del worker se valida y acota: no puede fabricar una coincidencia de firma ni provocar un aislamiento automático.
  Si el worker se cae o se cuelga con un archivo, se reporta como `Heuristic.AnalyzerFailure`. Si el worker no puede iniciarse, se usa el análisis en proceso como respaldo. No usa AppContainer: el aislamiento de red depende de la regla de firewall (que requiere administrador para crearse; si falla, el servicio lo registra como advertencia).
- La GUI aún se ejecuta como Administrador. Para reducir el riesgo, sus análisis manuales usan también el worker aislado y no procesan archivos hostiles en su propio proceso elevado. Un canal local servicio↔GUI con autorización por cliente (para que la GUI no necesite elevación) sigue pendiente: ejecutaría operaciones como SYSTEM a petición de usuarios locales y exige un diseño de seguridad cuidadoso.
- El motor YARA es un intérprete propio de un **subconjunto** de YARA (strings de texto/hex/regex, `N of`, `and/or/not`, `filesize`). Las reglas con módulos (`pe`, `uint16`, etc.) se descartan al cargar.
- Opera en modo usuario (post-operación): no puede bloquear la ejecución previa como un minifilter de kernel.
- La base de firmas incluida solo trae EICAR: use `update --online <url>` con una lista de hashes de su confianza (p. ej. un feed de abuse.ch MalwareBazaar con su `--auth-key`).
- El servicio registra detecciones y alertas en `%ProgramData%OpenGuardogsservice.log`; no muestra notificaciones emergentes (use la GUI o `openguard_cli logs`).
- El servicio solo aísla automáticamente lo **confirmado** (coincidencia de firma o riesgo crítico). Las sospechas heurísticas se registran sin tocar el archivo.

---

### 📥 Instalación (usuarios)

Descargue `OpenGuard_Setup_v<versión>.exe` desde la sección *Releases* (o desde el artefacto `OpenGuard-Installer` de la ejecución de GitHub Actions) y ejecútelo como Administrador. El instalador:

1. Copia `openguard_cli.exe`, `openguard_service.exe` y las firmas a `C:\Program Files\OpenGuard`.
2. Inicializa la base de firmas en `%ProgramData%\OpenGuard`.
3. Registra e inicia el servicio **OpenGuardService** (inicio automático, reinicio ante fallos).
4. Crea accesos directos y, opcionalmente, agrega OpenGuard al `PATH`.

> El instalador no está firmado digitalmente, por lo que SmartScreen puede mostrar una advertencia. Verifique el hash SHA-256 publicado junto al instalador.

---

### 💻 Uso del CLI

```text
openguard_cli scan <ruta>            Analiza un archivo o carpeta
openguard_cli quick                  Descargas, Escritorio, Documentos, Temp e Inicio
openguard_cli full                   Todas las unidades fijas
openguard_cli pe <ejecutable>        Informe estático PE (IAT, entropía, firma digital)
openguard_cli scan|quick|full ... --quarantine    Aísla amenazas de riesgo alto/crítico
openguard_cli quarantine list | restore <id> | delete <id>
openguard_cli vuln                   Auditoría de configuración de Windows
openguard_cli network                Auditoría de conexiones y archivo hosts
openguard_cli stats | update [json]  Estado e importación de firmas
openguard_cli update --online [url] [--auth-key K] [--name N]
                                     Descarga firmas por HTTPS (JSON de OpenGuard o lista de hashes)
openguard_cli status | logs [n]      Estado y registro del servicio de tiempo real
```

Códigos de salida: `0` sin amenazas · `1` error · `2` amenazas detectadas.

Gestionar la cuarentena y actualizar firmas requiere ejecutar la consola como **Administrador** (los datos en `%ProgramData%\OpenGuard` son de solo lectura para usuarios estándar, para que un proceso sin privilegios no pueda alterar las firmas ni la bóveda).

Servicio manual: `openguard_service.exe --install | --uninstall | --console` (este último ejecuta el motor en primer plano para depurar).

---

### 🏛️ Arquitectura

```
OpenGuard/
├── include/openguard/          # Encabezados públicos C++20
├── src/
│   ├── core/                   # openguard_core: firmas, escáner, PE, scripts, cuarentena, monitor, red, vulnerabilidades
│   ├── cli/                    # openguard_cli
│   └── service/                # openguard_service (Servicio de Windows)
├── tests/                      # Google Test
├── signatures/                 # hashes_index.json, manifest.sha256 y reglas YARA (evaluadas por yara_lite)
├── scripts/build_installer.ps1 # Compila, prueba y genera el instalador
├── installer.iss               # Script de Inno Setup
└── ROADMAP.md                  # Evolución hacia minifilter (Ring 0), AMSI, ETW
```

Datos en tiempo de ejecución (`%ProgramData%\OpenGuard`, redirigible con la variable `OPENGUARD_DATA_DIR`): `hashes.db`, `quarantine\`, `logs\service.log`.

---

### 🛠️ Compilación (desarrolladores)

**Requisitos:** Windows 10/11 x64 · Visual Studio 2022 (carga *Desarrollo para el escritorio con C++*) · CMake ≥ 3.22 · [vcpkg](https://github.com/microsoft/vcpkg) · (para el instalador) [Inno Setup 6](https://jrsoftware.org/isdl.php).

```powershell
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat

cd d:\APLICACIONES\OpenGuard
# Triplet ESTÁTICO: el runtime de C++ y SQLite van dentro de los .exe (sin VC++ Redistributable)
cmake -B build -S . -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="C:/vcpkg/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

Si prefiere el triplet dinámico (`x64-windows`), configure además `-DOPENGUARD_STATIC_RUNTIME=OFF`.

Binarios: `build\src\cli\Release\openguard_cli.exe`, `build\src\service\Release\openguard_service.exe`, `build\tests\Release\openguard_tests.exe`.

---

### 📦 Generar el instalador

Un solo comando compila, ejecuta las pruebas, prepara `dist\stage` y llama a Inno Setup:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_installer.ps1
```

Resultado: `dist\OpenGuard_Setup_v<versión>.exe` y su `.sha256`. La versión se toma de `CMakeLists.txt`.
Opciones: `-VcpkgRoot <ruta>`, `-SkipTests`, `-SkipBuild` (reutiliza `build\`).

En GitHub Actions el instalador se genera automáticamente y se publica como artefacto; al subir un tag `v*` se adjunta a la *Release*:

```powershell
git tag -a v0.2.0 -m "OpenGuard v0.2.0"
git push origin v0.2.0
```

---

### 🧪 Prueba defensiva con el archivo EICAR

> **AVISO**: nunca ejecute ni descargue malware real fuera de una máquina virtual aislada. EICAR es un archivo de prueba inofensivo estándar.

```powershell
Set-Content -Path "test_eicar.txt" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' -NoNewline
openguard_cli scan test_eicar.txt          # Detecta: EICAR-Standard-AV-Test-File
openguard_cli scan test_eicar.txt --quarantine
openguard_cli quarantine list
```

(Si Windows Defender está activo, puede aislar el archivo EICAR antes de que OpenGuard lo analice: use una carpeta excluida o una VM.)

---

<a name="english"></a>
## English

**OpenGuard** is a free, open-source defensive antivirus and security scanner for Windows 10/11 written in modern **C++20** with native Win32 APIs, Windows CNG (BCrypt), DPAPI and SQLite3.

> **Status (v0.2):** working user-mode engine (CLI + real-time protection service). The bundled signature database only contains the EICAR test file; load your own signatures with `openguard_cli update <file.json>`. YARA rules are evaluated by a built-in YARA subset interpreter; a native GUI (`openguard_gui.exe`) and ransomware decoy files are included.

### Capabilities
- **Multithreaded scanner** with batched processing (safe for full-disk scans) and SHA-256/SHA-1/MD5 signature lookup.
- **PE static analyzer** with a real import-table (IAT) parser, per-section entropy, W+X sections, packer detection, and Authenticode verification including **catalog-signed** Windows binaries. API *combinations* (remote injection, process hollowing, keylogger, downloader) are scored instead of isolated APIs, to limit false positives.
- **Script heuristics** for PowerShell, VBScript/JScript, Batch, HTA (AMSI bypass, download cradles, IEX, Base64, shadow-copy deletion).
- **Encrypted quarantine vault** (AES-256-CBC, DPAPI-protected key, SHA-256 integrity check on restore, secure wipe).
- **Real-time protection service** (`ReadDirectoryChangesW`) watching Downloads/Desktop/Documents/Temp, scanning USB drives on arrival, and auto-quarantining confirmed detections only.
- **System hardening audit** (SMBv1, UAC, Firewall, RDP, Guest) and **network audit** (C2 ports, hosts hijack, local proxy).

### Build & installer
```powershell
cmake -B build -S . -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="C:/vcpkg/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure

# Build + test + installer (requires Inno Setup 6)
powershell -ExecutionPolicy Bypass -File scripts\build_installer.ps1
```

Refer to [`ROADMAP.md`](ROADMAP.md) for technical documentation on user-mode limitations and kernel minifilter driver planning.
