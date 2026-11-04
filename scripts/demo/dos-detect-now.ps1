<#
  dos-detect-now.ps1 — one command: generate DoS-pattern traffic, run the REAL trained model on it,
  and forward the genuine detection to the dashboard. Takes ~15-20 seconds.

  This is NOT live wire capture (that needs Npcap). It is a freshly generated DoS capture scored by
  the real model — the detection and its evidence are genuine; it is labelled RECORDED TRAFFIC, not
  live. Nothing is sent on any network; only a capture file is written and analysed.

  Usage:
    powershell -ExecutionPolicy Bypass -File scripts\demo\dos-detect-now.ps1 -Email naajis@acme.com
#>
param(
  [Parameter(Mandatory = $true)][string]$Email,
  [int]$FloodSeconds = 20
)
$ErrorActionPreference = "Stop"
$repo    = "C:\SentinelIQ"
$sensor  = "$repo\sensor"
$bundle  = "C:\datasets\dos-models\dos-xgb-d0311-v1"
$pyS     = "$sensor\.venv\Scripts\python.exe"
$pyML    = "$repo\apps\ml-service\.venv\Scripts\python.exe"
$stamp   = Get-Date -Format "yyyyMMdd-HHmmss"
$work    = "$sensor\dos-demo\run-$stamp"
New-Item -ItemType Directory -Force -Path $work | Out-Null

# Run the sensor steps from the sensor directory so the `tools` and `netsensor` packages resolve.
Push-Location $sensor
try {
  Write-Host "[1/4] Generating $FloodSeconds s of DoS-pattern traffic (local-only, nothing is sent)..." -ForegroundColor Cyan
  & $pyS -m tools.generate_dos_pcap --out "$work\dos.pcap" --target-ip 127.0.0.1 --target-port 80 `
      --flood-seconds $FloodSeconds --flood-pps 6000 --benign-seconds 8 --benign-pps 60 --now
  if ($LASTEXITCODE -ne 0) { throw "generation failed" }

  Write-Host "[2/4] Extracting traffic windows with the real sensor..." -ForegroundColor Cyan
  & $pyS -m netsensor extract "$work\dos.pcap" --out-dir "$work\extract"
  if ($LASTEXITCODE -ne 0) { throw "extraction failed" }

  Write-Host "[3/4] Scoring every window with the trained model (dos-xgb-d0311-v1)..." -ForegroundColor Cyan
  & $pyML -m netsensor predict --bundle $bundle --extraction "$work\extract" --out-dir "$work\predict" `
      --organization-id 000000000000000000000000 --endpoint-id 000000000000000000000000
  if ($LASTEXITCODE -ne 0) { throw "scoring failed" }
}
finally {
  Pop-Location
}
if (-not (Test-Path "$work\predict\alerts.jsonl") -or ((Get-Item "$work\predict\alerts.jsonl").Length -eq 0)) {
  Write-Host "The model did not flag this capture (no alert). That is a real negative result, not an error." -ForegroundColor Yellow
  exit 0
}

Write-Host "[4/4] Forwarding the genuine detection to the dashboard as your organization..." -ForegroundColor Cyan
Push-Location $repo
& npm.cmd run replay:recorded -- --email $Email --alerts "$work\predict\alerts.jsonl"
Pop-Location

Write-Host "`nDone. Open the dashboard -> Detections. The DoS/DDoS detection is labelled RECORDED TRAFFIC + ML DETECTION (MITRE T1498)." -ForegroundColor Green
Write-Host "It is a real model detection on freshly generated traffic, not live wire capture." -ForegroundColor Green
