<#
.SYNOPSIS
  Podpisuje plik Authenticode (SHA-256, znacznik czasu RFC 3161) certyfikatem z magazynu Windows i sprawdza wynik.
.DESCRIPTION
  Certyfikat Certum w chmurze (SimplySign) pojawia się w magazynie CurrentUser\My po zalogowaniu w aplikacji
  SimplySign Desktop (kod z telefonu). Skrypt działa w Windows PowerShell 5.1 i w PowerShell 7.
  Na końcu wypisuje podmiot certyfikatu (to wartość authenticode_subject do manifestu wydania) i SHA-256 podpisanego
  pliku. Skrót liczy się DOPIERO po podpisie, bo podpis zmienia plik.
.EXAMPLE
  powershell -File agent/build/sign/sign.ps1 -File agent/bin/agent-0.2.1-windows-amd64.exe
#>
param(
  [Parameter(Mandatory = $true)][string]$File,
  # Odcisk certyfikatu. Bez niego skrypt bierze jedyny ważny certyfikat do podpisu kodu z magazynu.
  [string]$Thumbprint = "",
  [string]$TimestampUrl = "http://time.certum.pl",
  [string]$Description = "Piotr Melnyk IT - POMOC Zdalna",
  [string]$DescriptionUrl = "https://melnyk.pl"
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $File)) { throw "Nie ma pliku: $File" }
$File = (Resolve-Path -LiteralPath $File).Path

# signtool z Windows SDK: najnowszy zestaw x64.
$kits = Join-Path ${env:ProgramFiles(x86)} "Windows Kits"
$signtool = Get-ChildItem -Path (Join-Path $kits "10") -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -match "x64" } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "Brak signtool.exe. Zainstaluj Windows SDK (składnik Signing Tools for Desktop Apps)." }

# Wybór certyfikatu: tylko ważny, z prywatnym kluczem i przeznaczeniem Code Signing.
$codeSigningOid = "1.3.6.1.5.5.7.3.3"
$certs = @(Get-ChildItem Cert:CurrentUser/My | Where-Object {
    $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and ($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq $codeSigningOid })
  })
if ($Thumbprint) {
  $cert = $certs | Where-Object { $_.Thumbprint -eq ($Thumbprint -replace "\s", "") } | Select-Object -First 1
  if (-not $cert) { throw "Nie ma ważnego certyfikatu do podpisu kodu o odcisku $Thumbprint. Czy SimplySign Desktop jest zalogowany?" }
} elseif ($certs.Count -eq 1) {
  $cert = $certs[0]
} elseif ($certs.Count -eq 0) {
  throw "Brak ważnego certyfikatu do podpisu kodu. Zaloguj się w SimplySign Desktop (kod z telefonu) i spróbuj ponownie."
} else {
  $certs | ForEach-Object { Write-Host ("{0}  {1}" -f $_.Thumbprint, $_.Subject) }
  throw "Jest kilka certyfikatów. Podaj -Thumbprint."
}
Write-Host ("Certyfikat: {0}" -f $cert.Subject)

& $signtool.FullName sign /sha1 $cert.Thumbprint /fd sha256 /td sha256 /tr $TimestampUrl /d $Description /du $DescriptionUrl $File
if ($LASTEXITCODE -ne 0) { throw "signtool sign: kod $LASTEXITCODE" }

# Weryfikacja jak w systemie: łańcuch do zaufanego urzędu, znacznik czasu, domyślna polityka Authenticode.
& $signtool.FullName verify /pa /tw $File
if ($LASTEXITCODE -ne 0) { throw "signtool verify: kod $LASTEXITCODE" }
$sig = Get-AuthenticodeSignature -LiteralPath $File
if ($sig.Status -ne "Valid") { throw "Podpis nie jest ważny: $($sig.Status)" }

Write-Host ""
Write-Host "Podpisano i sprawdzono: $File"
Write-Host ("authenticode_subject: {0}" -f $sig.SignerCertificate.Subject)
Write-Host ("sha256 (po podpisie): {0}" -f (Get-FileHash -Algorithm SHA256 -LiteralPath $File).Hash.ToLower())
