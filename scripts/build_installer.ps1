<#
.SYNOPSIS
    Compila OpenGuard (Release, runtime estatico) y genera el instalador dist\OpenGuard_Setup_v<version>.exe.

.DESCRIPTION
    1. Configura y compila con CMake + Visual Studio 2022 + vcpkg (triplet x64-windows-static).
    2. Ejecuta las pruebas unitarias (omitible).
    3. Copia los binarios a dist\stage.
    4. Compila installer.iss con Inno Setup (ISCC.exe).

.PARAMETER VcpkgRoot
    Carpeta de vcpkg. Por defecto $env:VCPKG_ROOT, $env:VCPKG_INSTALLATION_ROOT o C:\vcpkg.

.PARAMETER SkipBuild
    No compila: usa los binarios ya existentes en build\ (util en CI tras el paso de compilacion).

.PARAMETER SkipTests
    No ejecuta ctest.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build_installer.ps1
#>
[CmdletBinding()]
param(
    [string]$VcpkgRoot,
    [string]$Config = 'Release',
    [switch]$SkipBuild,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Fail($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }
function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

# --- Version del proyecto (fuente unica: CMakeLists.txt) ---
$cmakeText = Get-Content (Join-Path $repo 'CMakeLists.txt') -Raw
if ($cmakeText -notmatch '(?s)project\(\s*OpenGuard\s+VERSION\s+(\d+\.\d+\.\d+)') { Fail 'No se pudo leer la version de CMakeLists.txt' }
$version = $Matches[1]
Write-Host "OpenGuard version $version"

$buildDir = Join-Path $repo 'build'
$stageDir = Join-Path $repo 'dist\stage'

if (-not $SkipBuild) {
    Step 'Localizando herramientas'
    if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
        Fail 'CMake no esta en el PATH. Instale CMake >= 3.22 (o abra "Developer PowerShell for VS 2022").'
    }

    if (-not $VcpkgRoot) {
        foreach ($c in @($env:VCPKG_ROOT, $env:VCPKG_INSTALLATION_ROOT, 'C:\vcpkg')) {
            if ($c -and (Test-Path (Join-Path $c 'scripts\buildsystems\vcpkg.cmake'))) { $VcpkgRoot = $c; break }
        }
    }
    if (-not $VcpkgRoot) { Fail 'No se encontro vcpkg. Indique -VcpkgRoot o defina VCPKG_ROOT (ver README).' }
    $toolchain = Join-Path $VcpkgRoot 'scripts\buildsystems\vcpkg.cmake'
    Write-Host "vcpkg: $VcpkgRoot"

    Step 'Configurando (CMake + vcpkg, triplet x64-windows-static)'
    & cmake -B $buildDir -S $repo -G 'Visual Studio 17 2022' -A x64 `
        "-DCMAKE_TOOLCHAIN_FILE=$toolchain" -DVCPKG_TARGET_TRIPLET=x64-windows-static -DBUILD_TESTING=ON
    if ($LASTEXITCODE -ne 0) { Fail 'Fallo la configuracion de CMake.' }

    Step "Compilando ($Config)"
    & cmake --build $buildDir --config $Config --parallel
    if ($LASTEXITCODE -ne 0) { Fail 'Fallo la compilacion.' }
}

if (-not $SkipTests) {
    Step 'Ejecutando pruebas unitarias'
    & ctest --test-dir $buildDir -C $Config --output-on-failure
    if ($LASTEXITCODE -ne 0) { Fail 'Las pruebas unitarias fallaron: no se genera el instalador.' }
}

Step 'Preparando binarios en dist\stage'
$cli = Join-Path $buildDir "src\cli\$Config\openguard_cli.exe"
$svc = Join-Path $buildDir "src\service\$Config\openguard_service.exe"
$gui = Join-Path $buildDir "src\gui\$Config\openguard_gui.exe"
foreach ($f in @($cli, $svc, $gui)) { if (-not (Test-Path $f)) { Fail "No se encontro $f (compile primero)." } }

if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force }
New-Item -ItemType Directory -Path $stageDir | Out-Null
Copy-Item $cli, $svc, $gui -Destination $stageDir

# El runtime es estatico: no deben existir dependencias de DLL que no sean del sistema
Step 'Verificando que los binarios no dependan de DLLs externas'
$dumpbin = Get-Command dumpbin -ErrorAction SilentlyContinue
if ($dumpbin) {
    foreach ($exe in Get-ChildItem $stageDir -Filter *.exe) {
        $deps = & dumpbin /dependents $exe.FullName | Select-String '\.dll' | ForEach-Object { $_.Line.Trim().ToLower() }
        $bad = $deps | Where-Object { $_ -match '^(vcruntime|msvcp|sqlite3|ucrtbased)' }
        if ($bad) { Fail "$($exe.Name) depende de: $($bad -join ', '). Use el triplet x64-windows-static." }
    }
    Write-Host 'OK'
} else {
    Write-Host '(dumpbin no disponible: verificacion omitida)'
}

Step 'Localizando Inno Setup'
$iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
if (-not $iscc) {
    foreach ($c in @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe")) {
        if (Test-Path $c) { $iscc = $c; break }
    }
}
if (-not $iscc) { Fail 'No se encontro ISCC.exe. Instale Inno Setup 6: https://jrsoftware.org/isdl.php (o: winget install JRSoftware.InnoSetup)' }
Write-Host "ISCC: $iscc"

Step 'Compilando el instalador'
& $iscc "/DMyAppVersion=$version" '/DStageDir=dist\stage' (Join-Path $repo 'installer.iss')
if ($LASTEXITCODE -ne 0) { Fail 'Inno Setup devolvio un error.' }

$setup = Join-Path $repo "dist\OpenGuard_Setup_v$version.exe"
if (-not (Test-Path $setup)) { Fail "No se genero $setup" }

$hash = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLower()
"$hash  $(Split-Path $setup -Leaf)" | Set-Content -Encoding ascii "$setup.sha256"

Write-Host "`nInstalador generado:" -ForegroundColor Green
Write-Host "  $setup ($([math]::Round((Get-Item $setup).Length / 1MB, 2)) MB)"
Write-Host "  SHA-256: $hash"
