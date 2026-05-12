# build-pro-dev.ps1 -- QA-ONLY ldflag-Pro Vaultify build.
#
# Customers receive Pro by activating a JWT license inside a regular
# release binary. This script exists so I can run end-to-end QA against
# Pro paths (Posture, validation Pro modal 402 vs 200, scheduled
# revalidation goroutine) without first issuing myself a license.
#
# DO NOT distribute the artefact this script produces. It is built
# with `BuildEdition=pro` linker tag and reports `(pro-qa)` in the
# banner so it can never be confused with a real release.
#
# Output:
#   dist/qa/vaultify_<version>_pro-qa_windows_amd64.exe
#   dist/qa/SHA256SUMS

[CmdletBinding()]
param([string] $Version)

$ErrorActionPreference = 'Stop'
$repoRoot = (Get-Item (Join-Path $PSScriptRoot '..')).FullName
Set-Location $repoRoot

if (-not $Version) {
    $bi = Get-Content -Raw 'internal/buildinfo/buildinfo.go'
    if ($bi -match 'BuildVersion\s*=\s*"([^"]+)"') { $Version = $Matches[1] }
    else { throw "Could not infer version from internal/buildinfo/buildinfo.go" }
}

$dist = Join-Path $repoRoot 'dist/qa'
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Path $dist | Out-Null

$ldflags = "-s -w -X github.com/vaultify/vaultify/internal/buildinfo.BuildVersion=$Version " +
           "-X github.com/vaultify/vaultify/internal/buildinfo.BuildEdition=pro"

Write-Host "==> Building QA Pro binary (windows/amd64)" -ForegroundColor Magenta
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$out = Join-Path $dist "vaultify_${Version}_pro-qa_windows_amd64.exe"
& go build -trimpath -ldflags $ldflags -o $out ./cmd/vaultify
if ($LASTEXITCODE -ne 0) { throw "go build failed" }
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
$size = [Math]::Round((Get-Item $out).Length / 1048576, 1)
Write-Host "    $(Split-Path -Leaf $out) => $size megabytes"

$hash = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
"$hash  $(Split-Path -Leaf $out)" | Set-Content -Path (Join-Path $dist 'SHA256SUMS') -Encoding ASCII
Write-Host ""
Write-Host "==> dist/qa/" -ForegroundColor Green
Get-ChildItem $dist | Format-Table Name, Length, LastWriteTime -AutoSize
Write-Host "Reminder: this binary is QA-only. Do not distribute." -ForegroundColor Yellow
