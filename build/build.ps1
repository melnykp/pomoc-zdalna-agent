#requires -Version 7
<#
.SYNOPSIS
  Buduje agent.exe (ten sam plik pełni rolę agenta i watchdoga) dla Windows amd64 bez CGO, ze wstrzykniętą wersją.
.EXAMPLE
  pwsh -File agent/build/build.ps1 -Version 0.1.0 -Server https://agent.example.pl -ServerKeys "srv-1=BASE64"
#>
param(
  [string]$Version = "0.0.0-dev",
  # Adres bramki agenta wkompilowany w plik (instalator z linku nie pyta o serwer).
  [string]$Server = "",
  # Zaufane klucze serwera: "id=base64,id2=base64". Z nimi agent ignoruje klucze z config.json.
  [string]$ServerKeys = "",
  # Zaufane klucze podpisu wydań (authorized_keys, wpisy rozdzielone średnikiem). Bez nich agent odrzuci każdą aktualizację.
  [string]$Signers = "",
  # Tylko rozwój i pilot bez certyfikatu kodu: pomija sprawdzanie Authenticode pobranych aktualizacji.
  # Podmiot certyfikatu kodu wkompilowany w plik (pin): aktualizacje muszą być podpisane właśnie nim, niezależnie od manifestu.
  [string]$SignerSubject = "",
  [switch]$AllowUnsigned,
  [string]$OutDir = (Join-Path $PSScriptRoot ".." "bin")
)
$ErrorActionPreference = "Stop"

$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$ldflags = "-s -w -H=windowsgui -X main.version=$Version"
if ($Server) { $ldflags += " -X main.defaultServer=$Server" }
if ($ServerKeys) { $ldflags += " -X github.com/melnykp/pomoc-zdalna-agent/internal/trust.Compiled=$ServerKeys" }
# Klucze zawierają spacje, więc wartość musi być w apostrofach (składnia -ldflags).
if ($Signers) { $ldflags += " -X 'github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig.CompiledSigners=$Signers'" }
if ($SignerSubject) { $ldflags += " -X 'github.com/melnykp/pomoc-zdalna-agent/internal/update.AuthenticodeSubjectPin=$SignerSubject'" }
if ($AllowUnsigned) { $ldflags += " -X github.com/melnykp/pomoc-zdalna-agent/internal/update.RequireAuthenticode=false" }

# Zasoby pliku .exe: ikona z melnyk.pl i właściwości (firma, nazwa produktu, wersja). Plik .syso lądzi obok
# pakietu main i jest dołączany przez linker automatycznie; nie wchodzi do repozytorium.
$base = $Version -replace '[-+].*$', ''
$parts = @($base.Split('.') + '0', '0', '0', '0')[0..3] | ForEach-Object { if ($_ -match '^\d+$') { [int]$_ } else { 0 } }
$syso = Join-Path $PSScriptRoot ".." "cmd" "agent" "resource_windows_amd64.syso"
Push-Location $PSScriptRoot
try {
  go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.1 -64 -o $syso `
    "-ver-major=$($parts[0])" "-ver-minor=$($parts[1])" "-ver-patch=$($parts[2])" "-ver-build=$($parts[3])" `
    "-product-ver-major=$($parts[0])" "-product-ver-minor=$($parts[1])" "-product-ver-patch=$($parts[2])" "-product-ver-build=$($parts[3])" `
    "-file-version=$Version" "-product-version=$Version" versioninfo.json
  if ($LASTEXITCODE -ne 0) { throw "goversioninfo: kod $LASTEXITCODE" }
} finally {
  Pop-Location
}

Push-Location (Join-Path $PSScriptRoot "..")
try {
  go build -trimpath -ldflags $ldflags -o (Join-Path $OutDir "agent-$Version-windows-amd64.exe") ./cmd/agent
  if ($LASTEXITCODE -ne 0) { throw "go build agent: kod $LASTEXITCODE" }
} finally {
  Pop-Location
}

Get-ChildItem -Path $OutDir -Filter "agent-$Version-windows-amd64.exe" |
  Get-FileHash -Algorithm SHA256 |
  ForEach-Object { "{0}  {1}" -f $_.Hash.ToLower(), (Split-Path $_.Path -Leaf) }

Write-Host ""
Write-Host "Podpis Authenticode: build/sign/ (osobny krok w CI). Manifest wydania: tools/release-sign na stacji z YubiKey."
