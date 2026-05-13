# build-release.ps1 -- Windows-native equivalent of `make all`.
#
# Cross-compiles every release target into dist/, regenerates the
# Windows .syso resource (so the embedded icon stays in sync), produces
# the macOS .icns + Linux hicolor PNG set + .desktop template, wraps
# each darwin binary in a Vaultify.app bundle, and writes a SHA256SUMS.
#
# Requires:
#   - Go (any version go.mod targets)
#   - rsrc on $PATH for the Windows .syso. Install once with:
#       go install github.com/akavel/rsrc@latest
#
# Output (under dist/):
#   vaultify_<v>_windows_amd64.exe   (icon embedded via .syso)
#   vaultify_<v>_darwin_amd64
#   vaultify_<v>_darwin_arm64
#   vaultify_<v>_linux_amd64
#   vaultify_<v>_linux_arm64
#   Vaultify.icns
#   linux-icons/                     (hicolor PNG set + .desktop)
#   vaultify_<v>_linux-icons.tar.gz  (only when `tar` is on PATH)
#   Vaultify-amd64.app/              (.app bundle ready to ship)
#   Vaultify-arm64.app/
#   SHA256SUMS

[CmdletBinding()]
param(
    [string] $Version,
    [switch] $SkipIcons,
    [switch] $SkipBundles
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Get-Item (Join-Path $PSScriptRoot '..')).FullName
Set-Location $repoRoot

# Default the version from internal/buildinfo so this script and the
# Makefile stay in lockstep without anyone hand-editing both.
if (-not $Version) {
    $bi = Get-Content -Raw 'internal/buildinfo/buildinfo.go'
    if ($bi -match 'BuildVersion\s*=\s*"([^"]+)"') {
        $Version = $Matches[1]
    } else {
        throw "Could not infer version from internal/buildinfo/buildinfo.go"
    }
}
Write-Host "==> Vaultify release build" -ForegroundColor Cyan
Write-Host "    version: $Version"
Write-Host "    repo:    $repoRoot"

$dist = Join-Path $repoRoot 'dist'
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Path $dist | Out-Null

$ldflagsCommon = "-s -w -X github.com/vaultify/vaultify/internal/buildinfo.BuildVersion=$Version"
# Single open-source binary: no extra linker overrides on release artefacts.
$ldflagsRelease = $ldflagsCommon

function Build-VaultifyIcons {
    param([string] $DistDir)

    Write-Host "==> Generating icon assets" -ForegroundColor Cyan

    & go run ./tools/icogen -format ico -in internal/web/assets/vaultify_logo.png -out cmd/vaultify/vaultify.ico
    if ($LASTEXITCODE -ne 0) { throw "icogen ico failed (exit=$LASTEXITCODE)" }

    $rsrc = Get-Command rsrc -ErrorAction SilentlyContinue
    if ($rsrc) {
        & $rsrc.Source -ico cmd/vaultify/vaultify.ico -arch amd64 -o cmd/vaultify/rsrc_windows_amd64.syso
        Write-Host "    .syso refreshed"
    } else {
        Write-Warning "rsrc not on PATH; .syso left as-is. Install with: go install github.com/akavel/rsrc@latest"
    }

    $icnsOut = Join-Path $DistDir 'Vaultify.icns'
    Write-Host "    icns -> $icnsOut"
    & go run ./tools/icogen -format icns -in internal/web/assets/vaultify_logo.png -out $icnsOut
    if ($LASTEXITCODE -ne 0) { throw "icogen icns failed (exit=$LASTEXITCODE)" }

    $linuxOut = Join-Path $DistDir 'linux-icons'
    Write-Host "    png-set -> $linuxOut"
    & go run ./tools/icogen -format png-set -in internal/web/assets/vaultify_logo.png -out $linuxOut
    if ($LASTEXITCODE -ne 0) { throw "icogen png-set failed (exit=$LASTEXITCODE)" }
}

function Build-VaultifyBinaries {
    param([string] $DistDir, [string] $Ldflags, [string] $Ver, [string] $EditionTag)

    $env:CGO_ENABLED = '0'
    $targets = @(
        @{ goos = 'windows'; goarch = 'amd64'; suffix = '.exe' },
        @{ goos = 'darwin';  goarch = 'amd64'; suffix = ''     },
        @{ goos = 'darwin';  goarch = 'arm64'; suffix = ''     },
        @{ goos = 'linux';   goarch = 'amd64'; suffix = ''     },
        @{ goos = 'linux';   goarch = 'arm64'; suffix = ''     }
    )
    # `release` is the standard tag and is omitted from the filename
    # so asset names stay short. Other edition tags are surfaced in the
    # filename when used for non-release builds.
    $tagSuffix = ''
    if ($EditionTag -and $EditionTag -ne 'release') { $tagSuffix = "_$EditionTag" }

    foreach ($t in $targets) {
        $env:GOOS = $t.goos
        $env:GOARCH = $t.goarch
        $name = "vaultify_${Ver}${tagSuffix}_$($t.goos)_$($t.goarch)$($t.suffix)"
        $out = Join-Path $DistDir $name
        Write-Host "==> Building $($t.goos)/$($t.goarch)" -ForegroundColor Cyan
        & go build -trimpath -ldflags $Ldflags -o $out ./cmd/vaultify
        if ($LASTEXITCODE -ne 0) { throw "go build failed for $($t.goos)/$($t.goarch)" }
        $size = [Math]::Round((Get-Item $out).Length / 1048576, 1)
        Write-Host "    $name => $size megabytes"
    }
    Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
}

function Build-VaultifyMacBundles {
    param([string] $DistDir, [string] $Ver, [string] $EditionTag)

    $tagSuffix = ''
    $appTagSuffix = ''
    if ($EditionTag -and $EditionTag -ne 'release') {
        $tagSuffix = "_$EditionTag"
        $appTagSuffix = "-$EditionTag"
    }

    Write-Host "==> Building macOS .app bundles" -ForegroundColor Cyan
    foreach ($arch in @('amd64', 'arm64')) {
        $bin = Join-Path $DistDir "vaultify_${Ver}${tagSuffix}_darwin_${arch}"
        if (-not (Test-Path $bin)) { continue }
        $appDir = Join-Path $DistDir "Vaultify${appTagSuffix}-${arch}.app"
        $contentsMacOS = Join-Path $appDir 'Contents/MacOS'
        $contentsRes   = Join-Path $appDir 'Contents/Resources'
        New-Item -ItemType Directory -Path $contentsMacOS -Force | Out-Null
        New-Item -ItemType Directory -Path $contentsRes   -Force | Out-Null
        Copy-Item $bin (Join-Path $contentsMacOS 'vaultify') -Force
        $icns = Join-Path $DistDir 'Vaultify.icns'
        if (Test-Path $icns) { Copy-Item $icns (Join-Path $contentsRes 'AppIcon.icns') -Force }

        # Build the plist as an array of single-quoted strings: PS 5.1
        # will mis-parse a here-string with `>` as a redirection, and
        # mis-parse `<key>` inside a double-quoted string as the `<`
        # operator. Single quotes + concat dodge both bugs.
        $plistLines = @(
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
            '<plist version="1.0"><dict>',
            '  <key>CFBundleName</key><string>Vaultify</string>',
            '  <key>CFBundleDisplayName</key><string>Vaultify</string>',
            '  <key>CFBundleIdentifier</key><string>app.vaultify.cli</string>',
            '  <key>CFBundleExecutable</key><string>vaultify</string>',
            '  <key>CFBundleIconFile</key><string>AppIcon</string>',
            '  <key>CFBundlePackageType</key><string>APPL</string>',
            ('  <key>CFBundleShortVersionString</key><string>' + $Ver + '</string>'),
            ('  <key>CFBundleVersion</key><string>' + $Ver + '</string>'),
            '  <key>LSMinimumSystemVersion</key><string>10.15</string>',
            '  <key>NSHighResolutionCapable</key><true/>',
            '</dict></plist>'
        )
        $plist = ($plistLines -join "`n")
        Set-Content -Path (Join-Path $appDir 'Contents/Info.plist') -Value $plist -NoNewline -Encoding UTF8
        Write-Host "    Vaultify${appTagSuffix}-${arch}.app"
    }

    $tar = Get-Command tar -ErrorAction SilentlyContinue
    $linuxIcons = Join-Path $DistDir 'linux-icons'
    if ($tar -and (Test-Path $linuxIcons)) {
        $tarball = Join-Path $DistDir "vaultify_${Ver}${tagSuffix}_linux-icons.tar.gz"
        Push-Location $DistDir
        try { & $tar.Source -czf $tarball 'linux-icons' } finally { Pop-Location }
        Write-Host "    vaultify_${Ver}${tagSuffix}_linux-icons.tar.gz"
    } elseif (-not $tar) {
        Write-Warning "tar not found; skipping linux-icons.tar.gz; ship the linux-icons/ directory directly."
    }
}

# Single-binary release: one dist/ tree for all platforms.
if (-not $SkipIcons)   { Build-VaultifyIcons   -DistDir $dist }
Build-VaultifyBinaries -DistDir $dist -Ldflags $ldflagsRelease -Ver $Version -EditionTag 'release'
if (-not $SkipBundles) { Build-VaultifyMacBundles -DistDir $dist -Ver $Version -EditionTag 'release' }

Write-Host "==> Writing SHA256SUMS" -ForegroundColor Cyan
$hashLines = Get-ChildItem $dist -File | Where-Object { $_.Name -match '^vaultify_' -or $_.Name -eq 'Vaultify.icns' } | Sort-Object Name | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "$hash  $($_.Name)"
}
$sumsPath = Join-Path $dist 'SHA256SUMS'
$hashLines | Set-Content -Path $sumsPath -Encoding ASCII

Write-Host ""
Write-Host "==> dist/" -ForegroundColor Green
Get-ChildItem $dist | Sort-Object Name | Format-Table Name, Length, LastWriteTime -AutoSize
Write-Host "==> SHA256SUMS" -ForegroundColor Green
Get-Content $sumsPath
