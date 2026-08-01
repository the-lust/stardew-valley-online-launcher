param(
    [string]$File = "game.exe",
    [string]$KeyFile = ".vtkey"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$file = Join-Path $root $File
if (-not (Test-Path -LiteralPath $file)) { Write-Error "file not found: $file"; exit 1 }

$key = (Get-Content -LiteralPath (Join-Path $root $KeyFile) -Raw).Trim()
if (-not $key) { Write-Error "no API key in $KeyFile"; exit 1 }

$headers = @{ "x-apikey" = $key }

Write-Host "[vt] uploading $File ..."
$json = & curl.exe -s -X POST "https://www.virustotal.com/api/v3/files" `
    -H "x-apikey: $key" -F "file=@$file;type=application/octet-stream"
$resp = $json | ConvertFrom-Json
if (-not $resp.data.id) {
    Write-Host "[vt] upload failed: $json"
    exit 1
}
$id = $resp.data.id
Write-Host "[vt] analysis id: $id"

for ($i = 0; $i -lt 12; $i++) {
    Start-Sleep -Seconds 20
    try {
        $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/analyses/$id" -Headers $headers
    } catch {
        continue
    }
    if ($r.data.attributes.status -eq "completed") { break }
}

if ($r.data.attributes.status -ne "completed") {
    Write-Host "[vt] timed out waiting for analysis"
    exit 1
}

$stats = $r.data.attributes.stats
$results = $r.data.attributes.results
Write-Host ""
Write-Host "=== VIRUSTOTAL RESULT ==="
Write-Host ("  malicious:  {0}" -f $stats.malicious)
Write-Host ("  suspicious: {0}" -f $stats.suspicious)
Write-Host ("  undetected: {0}" -f $stats.undetected)
Write-Host ("  harmless:   {0}" -f $stats.harmless)
$flagged = @($results.PSObject.Properties | Where-Object {
    $_.Value.category -eq "malicious" -or $_.Value.category -eq "suspicious"
})
if ($flagged.Count -gt 0) {
    Write-Host ""
    Write-Host "  FLAGGED BY:"
    foreach ($f in $flagged) {
        Write-Host ("    {0}: [{1}] {2}" -f $f.Name, $f.Value.category, $f.Value.result)
    }
    exit 2
} else {
    Write-Host ""
    Write-Host "  CLEAN: 0 flags"
    exit 0
}
