# axon - Ultimate Easy Start
$ErrorActionPreference = "Stop"
Write-Host "🚀 Starting axon Super-Easy Setup..." -ForegroundColor Cyan

# 1. Build the engine
Write-Host "🛠️  Building the engine..." -ForegroundColor Yellow
cd axon
go build -o axon.exe ./cmd/axon
cd ..

# 2. Setup Global Path
Write-Host "🌍  Setting up global access..." -ForegroundColor Yellow
$InstallDir = $PSScriptRoot
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path += ";$InstallDir"
}

# 3. Run a "Magic Scan" Demo
Write-Host "🔍  Running automatic demo scan on examples..." -ForegroundColor Cyan
./axon/axon.exe scan -i axon/examples/complex.sarif -o DEMO_REPORT.md

Write-Host "`n✅  SUCCESS! axon is installed and the scan is complete." -ForegroundColor Green
Write-Host "📄  Opening your first security report: DEMO_REPORT.md" -ForegroundColor White

# 4. Open the report automatically
Start-Process "DEMO_REPORT.md"

