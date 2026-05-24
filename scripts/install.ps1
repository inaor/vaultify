# Install or upgrade Vaultify from GitHub Releases (Windows).
# Installs vaultify.exe and adds it to the current user's PATH.
#
# Usage (PowerShell):
#   irm https://raw.githubusercontent.com/securityjoes/vaultify/main/scripts/install.ps1 | iex
#   .\scripts\install.ps1
param(
    [string]$Repo = $(if ($env:VAULTIFY_REPO) { $env:VAULTIFY_REPO } else { 'securityjoes/vaultify' }),
    [string]$InstallDir = $(if ($env:VAULTIFY_INSTALL_DIR) { $env:VAULTIFY_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\Vaultify\bin' })
)

$ErrorActionPreference = 'Stop'

function Get-LatestVersion {
    $url = "https://raw.githubusercontent.com/$Repo/main/releases/latest.json"
    $manifest = Invoke-RestMethod -Uri $url -UseBasicParsing
    if (-not $manifest.version) {
        throw "Could not read version from $url"
    }
    return [string]$manifest.version
}

function Test-PathContains([string]$Dir) {
  $parts = ($env:Path -split ';') | Where-Object { $_ -and ($_.TrimEnd('\') -ieq $Dir.TrimEnd('\')) }
  return $parts.Count -gt 0
}

function Ensure-UserPath([string]$Dir) {
  if (Test-PathContains $Dir) {
    Write-Host "PATH already includes $Dir"
    return
  }
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if ([string]::IsNullOrWhiteSpace($userPath)) {
    $newPath = $Dir
  } else {
    $newPath = "$Dir;$userPath"
  }
  [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
  $env:Path = "$Dir;$env:Path"
  Write-Host "Added $Dir to your user PATH."
  Write-Host "Open a new terminal, then type: vaultify"
}

$version = Get-LatestVersion
$asset = "vaultify_${version}_windows_amd64.exe"
$downloadUrl = "https://github.com/$Repo/releases/download/v$version/$asset"
$dest = Join-Path $InstallDir 'vaultify.exe'

Write-Host "Installing Vaultify v$version for windows_amd64..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Invoke-WebRequest -Uri $downloadUrl -OutFile $dest -UseBasicParsing

Ensure-UserPath $InstallDir

Write-Host ""
Write-Host "Installed $dest"
if (Get-Command vaultify -ErrorAction SilentlyContinue) {
  Write-Host "Ready: $(Get-Command vaultify | Select-Object -ExpandProperty Source)"
  & vaultify -version
} else {
  Write-Host "Open a new PowerShell or Command Prompt, then run: vaultify"
}
