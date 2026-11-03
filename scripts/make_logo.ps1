<#
.SYNOPSIS  Genera el logo de OpenGuard (assets\logo.png y assets\openguard.ico multi-resolucion).
#>
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'
$assets = Join-Path (Split-Path -Parent $PSScriptRoot) 'assets'
New-Item -ItemType Directory -Force $assets | Out-Null

function New-LogoBitmap([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)
    $s = [double]$size

    # Escudo (coordenadas relativas)
    $pts = @(
        @(0.50,0.04), @(0.86,0.17), @(0.86,0.50), @(0.80,0.70), @(0.66,0.86), @(0.50,0.96),
        @(0.34,0.86), @(0.20,0.70), @(0.14,0.50), @(0.14,0.17)
    )
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $poly = @(); foreach ($p in $pts) { $poly += New-Object System.Drawing.PointF ([single]($p[0]*$s)), ([single]($p[1]*$s)) }
    $path.AddCurve($poly, 0.35) | Out-Null
    $path.CloseFigure()

    $rect = New-Object System.Drawing.RectangleF 0,0,$s,$s
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect, ([System.Drawing.Color]::FromArgb(255,0,200,160)), ([System.Drawing.Color]::FromArgb(255,0,92,140)), 70.0
    $g.FillPath($grad, $path)

    # Borde interior claro
    $penW = [single][Math]::Max(1.0, $s*0.025)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(90,255,255,255)), $penW
    $g.DrawPath($pen, $path)

    # Brillo superior
    $hl = New-Object System.Drawing.Drawing2D.GraphicsPath
    $hl.AddEllipse([single](0.20*$s), [single](-0.30*$s), [single](0.60*$s), [single](0.55*$s))
    $g.SetClip($path)
    $g.FillPath((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(45,255,255,255))), $hl)
    $g.ResetClip()

    # Marca de verificacion
    $wCheck = [single][Math]::Max(2.0, $s*0.085)
    $chk = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), $wCheck
    $chk.StartCap = 'Round'; $chk.EndCap = 'Round'; $chk.LineJoin = 'Round'
    $g.DrawLines($chk, @(
        (New-Object System.Drawing.PointF ([single](0.31*$s)), ([single](0.50*$s))),
        (New-Object System.Drawing.PointF ([single](0.45*$s)), ([single](0.65*$s))),
        (New-Object System.Drawing.PointF ([single](0.70*$s)), ([single](0.36*$s)))
    ))
    $g.Dispose()
    return $bmp
}

$sizes = 16,24,32,48,64,128,256
$pngs = @{}
foreach ($sz in $sizes) {
    $bmp = New-LogoBitmap $sz
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngs[$sz] = $ms.ToArray()
    if ($sz -eq 256) { $bmp.Save((Join-Path $assets 'logo.png'), [System.Drawing.Imaging.ImageFormat]::Png) }
    $bmp.Dispose()
}

# ICO con imagenes PNG incrustadas
$out = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter $out
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
foreach ($sz in $sizes) {
    $data = $pngs[$sz]
    $dim = if ($sz -ge 256) { 0 } else { $sz }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$data.Length); $bw.Write([uint32]$offset)
    $offset += $data.Length
}
foreach ($sz in $sizes) { $bw.Write($pngs[$sz]) }
$bw.Flush()
[System.IO.File]::WriteAllBytes((Join-Path $assets 'openguard.ico'), $out.ToArray())
Write-Host "Logo generado en $assets"
