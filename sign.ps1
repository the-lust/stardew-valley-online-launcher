param(
    [string]$File = "game.exe",
    [string]$TokenFile = ".signtoken",
    [string]$Endpoint = "https://sign.necessary.nu/windows/sign"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.CommandPath
$file = Join-Path $root $File
$token = (Get-Content -LiteralPath (Join-Path $root $TokenFile) -Raw).Trim()

if (-not (Test-Path -LiteralPath $file)) { Write-Error "file not found: $file"; exit 1 }
if (-not $token) { Write-Error "no signing token in $TokenFile"; exit 1 }

$ossl = Get-Command osslsigncode -ErrorAction SilentlyContinue
if (-not $ossl) { Write-Error "osslsigncode not found on PATH"; exit 1 }

$tmp = Join-Path $env:TEMP "game-sign-$(Get-Random)"
New-Item -ItemType Directory -Path $tmp | Out-Null
$tosign = Join-Path $tmp "tosign.bin"
$signed = Join-Path $tmp "signed.bin"
$out = Join-Path $root "game-signed.exe"

Write-Host "[sign] extracting data to be signed ..."
& $ossl.Source extract-data -in $file -out $tosign
if ($LASTEXITCODE -ne 0) { Write-Error "extract-data failed"; exit 1 }

Write-Host "[sign] sending to signing service ..."
& curl.exe -s -X POST -H "Authorization: Bearer $token" --data-binary "@$tosign" $Endpoint -o $signed
if (-not (Test-Path -LiteralPath $signed)) { Write-Error "signing request failed (no response file)"; exit 1 }

Write-Host "[sign] attaching signature ..."
& $ossl.Source attach-signature -sigin $signed -in $file -out $out
if ($LASTEXITCODE -ne 0) { Write-Error "attach-signature failed"; exit 1 }

Remove-Item -LiteralPath $tmp -Recurse -Force

$sig = Get-AuthenticodeSignature -LiteralPath $out
Write-Host ""
Write-Host "[sign] result: $($sig.Status)"
Write-Host "[sign] signer:  $($sig.SignerCertificate.Subject)"
if ($sig.Status -ne "Valid") { exit 1 }

if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
Move-Item -LiteralPath $out -Destination $file
Write-Host "[sign] signed binary: $file"
exit 0
