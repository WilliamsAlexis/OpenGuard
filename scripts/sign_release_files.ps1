<#
.SYNOPSIS
    Firma los archivos de actualizacion de OpenGuard (indice de firmas y manifiesto de reglas YARA) con ECDSA P-256.

.DESCRIPTION
    Regenera signatures\rules_manifest.json (nombre + SHA-256 de cada regla) y crea los archivos .sig
    (base64 de r||s, 64 bytes) para:
        signatures\hashes_index.json
        signatures\rules_manifest.json
    Debe ejecutarse CADA VEZ que se modifique el indice de firmas o alguna regla, antes de hacer commit.
    La clave privada vive FUERA del repositorio: %USERPROFILE%\.openguard-signing\private.blob
    (haga copia de seguridad en un lugar seguro: si se pierde, hay que generar otra clave y publicar una nueva version
    del programa con la nueva clave publica; si se filtra, cualquiera podria publicar actualizaciones "validas").

    Las firmas se calculan sobre el contenido con saltos de linea LF (como lo sirve GitHub), por eso
    .gitattributes fuerza LF en signatures\.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\sign_release_files.ps1
#>
[CmdletBinding()]
param(
    [string]$KeyFile = (Join-Path $env:USERPROFILE '.openguard-signing\private.blob')
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$sigDir = Join-Path $repo 'signatures'

if (-not (Test-Path $KeyFile)) { Write-Host "[ERROR] No se encontro la clave privada: $KeyFile" -ForegroundColor Red; exit 1 }

function Get-Lf([string]$path) {
    $text = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
    return [Text.Encoding]::UTF8.GetBytes(($text -replace "`r`n", "`n"))
}

# --- 1. Manifiesto de reglas YARA ---
$files = @()
foreach ($f in Get-ChildItem (Join-Path $sigDir 'yara_rules') -Filter *.yar | Sort-Object Name) {
    $bytes = Get-Lf $f.FullName
    $hash = ([Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    $files += [ordered]@{ name = $f.Name; sha256 = $hash }
}
$manifest = [ordered]@{ version = (Get-Date -Format 'yyyy.MM.dd.HHmm'); files = $files }
$manifestJson = ($manifest | ConvertTo-Json -Depth 5 -Compress)
[IO.File]::WriteAllText((Join-Path $sigDir 'rules_manifest.json'), $manifestJson + "`n", (New-Object Text.UTF8Encoding($false)))

# --- 2. Firmas ---
$blob = [Convert]::FromBase64String(([IO.File]::ReadAllText($KeyFile)).Trim())
$key = [Security.Cryptography.CngKey]::Import($blob, [Security.Cryptography.CngKeyBlobFormat]::EccPrivateBlob)
$ec = New-Object Security.Cryptography.ECDsaCng $key

foreach ($name in 'hashes_index.json', 'rules_manifest.json') {
    $path = Join-Path $sigDir $name
    $data = Get-Lf $path
    $sig = $ec.SignData($data, [Security.Cryptography.HashAlgorithmName]::SHA256)
    if ($sig.Length -ne 64) { Write-Host "[ERROR] Firma con longitud inesperada ($($sig.Length))" -ForegroundColor Red; exit 1 }
    [IO.File]::WriteAllText("$path.sig", [Convert]::ToBase64String($sig), (New-Object Text.UTF8Encoding($false)))

    # Verificacion inmediata con la clave publica derivada de la privada
    if (-not $ec.VerifyData($data, $sig, [Security.Cryptography.HashAlgorithmName]::SHA256)) { Write-Host "[ERROR] La firma de $name no verifica" -ForegroundColor Red; exit 1 }
    Write-Host "Firmado: signatures\$name.sig"
}
Write-Host "`nListo. Haga commit de signatures\*.sig y signatures\rules_manifest.json junto con los cambios." -ForegroundColor Green
