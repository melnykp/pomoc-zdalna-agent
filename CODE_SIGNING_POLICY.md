# Polityka podpisywania kodu

Ta strona opisuje, kto i jak podpisuje pliki wykonywalne agenta wydawane z tego repozytorium.

## Kto podpisuje

Wydania podpisuje wyłącznie opiekun projektu, **Piotr Melnyk** ([melnyk.pl](https://melnyk.pl)), na własny certyfikat
do podpisu kodu wystawiony przez Certum. Nikt inny nie ma dostępu do klucza podpisu. Klucz jest przechowywany w chmurowym
module HSM (Certum SimplySign) i wymaga potwierdzenia kodem z telefonu opiekuna przy każdej sesji podpisywania.

Do czasu wystawienia certyfikatu pliki z tego repozytorium nie są podpisane. Ta polityka obowiązuje od pierwszego
podpisanego wydania.

## Co jest podpisywane

- Tylko plik `agent.exe` zbudowany z tagu wydania w tym repozytorium (`go build` przez `build/build.ps1`, bez zmian poza
  wkompilowanym adresem serwera i kluczem serwera).
- Żaden kod spoza tego repozytorium i żaden zamknięty komponent nie jest podpisywany tym certyfikatem.

## Jak powstaje podpisane wydanie

1. Opiekun oznacza commit tagiem wersji, a CI uruchamia testy.
2. Plik jest budowany z tagu skryptem `build/build.ps1`.
3. Opiekun podpisuje plik skryptem `build/sign/sign.ps1`: SHA-256 i znacznik czasu RFC 3161, a skrypt sprawdza podpis.
4. Suma SHA-256 policzona **po** podpisie trafia do opisu wydania.

## Jak sprawdzić podpis

W PowerShellu:

```
Get-AuthenticodeSignature .\agent.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

`Status` musi mieć wartość `Valid`, a podmiot certyfikatu zgadzać się z podanym w opisie wydania. Sumę pliku porównaj z
opisem wydania: `Get-FileHash .\agent.exe -Algorithm SHA256`.

## Prywatność i bezpieczeństwo

Agent nie wysyła danych nigdzie poza serwerem wkompilowanym w plik. Co dokładnie zbiera: [docs/PRIVACY.md](docs/PRIVACY.md).
Wykryty złośliwy lub wadliwy plik podpisany tym certyfikatem należy zgłosić według [SECURITY.md](SECURITY.md).
W razie podejrzenia kompromitacji klucza opiekun unieważnia certyfikat u wystawcy i publikuje komunikat w repozytorium.
