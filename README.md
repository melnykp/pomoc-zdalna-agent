# Piotr Melnyk IT - POMOC Zdalna: agent

Agent zdalnej pomocy technicznej i monitoringu komputerów z Windows, napisany w Go. Działa jako usługa na komputerze klienta,
zgłasza stan maszyny (procesor, pamięć, dyski, zainstalowane programy) do serwera inżyniera, przyjmuje kilka ściśle
określonych poleceń i sam się aktualizuje według podpisanych wydań. Zdalny pulpit (moduł oparty na RustDesk) jest
planowany i jeszcze go tu nie ma.

Autor i opiekun: **Piotr Melnyk** ([melnyk.pl](https://melnyk.pl)), firma **Piotr Melnyk IT**. Agent jest częścią usługi
„POMOC Zdalna” świadczonej przez autora. Kod agenta jest otwarty, żeby każdy mógł sprawdzić, co działa na jego
komputerze. Serwer i panel inżyniera są osobnymi, prywatnymi projektami. Agent mówi z nimi publicznie opisanym protokołem
([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)).

> **English summary.** Open-source Windows agent (Go) for remote IT support and monitoring: a LocalSystem service plus a
> watchdog, mutual Ed25519 authentication with a server key compiled into the binary, a small fixed set of commands (no
> arbitrary code execution), and an update chain with signed manifests (sshsig), SHA-256, Authenticode verification and
> automatic rollback. Licensed under Apache-2.0. See `docs/ARCHITECTURE.md`, `docs/PRIVACY.md` and
> `CODE_SIGNING_POLICY.md`.

## Co robi

- Uruchamia się jako dwie usługi Windows: agent i nadzorca (watchdog). To ten sam plik `agent.exe` w dwóch rolach.
- Rejestruje komputer na serwerze z jednorazowego zaproszenia, a inżynier zatwierdza go w panelu.
- Co 30 sekund wysyła stan (procesor, pamięć, czas działania, zalogowany użytkownik), a co kilka godzin inwentaryzację.
- Wykonuje tylko polecenia z listy: odświeżenie inwentaryzacji, sprawdzenie i zastosowanie aktualizacji, restart agenta,
  zmiana ustawień, wycofanie agenta. Nie uruchamia dowolnych poleceń ani skryptów.
- Aktualizuje się tylko do wydań podpisanych kluczem właściciela i plików z ważnym podpisem Authenticode. Wadliwa
  aktualizacja kończy się powrotem do poprzedniej wersji.

Dokładnie, jakie dane agent zbiera i dokąd je wysyła: [docs/PRIVACY.md](docs/PRIVACY.md).

## Budowanie

Wymagania: Go 1.26 lub nowszy. Testy działają na Windows i Linuksie.

```
go vet ./...
go test ./...
```

Plik dla Windows z wkompilowanym adresem serwera i kluczem serwera (PowerShell 7, Windows):

```
pwsh -File build/build.ps1 -Version 1.0.0 -Server https://twoj-serwer.example -ServerKeys "id=BASE64_KLUCZA_PUBLICZNEGO"
```

Skrypt dołącza ikonę i właściwości pliku (nazwa, firma, wersja) i buduje bez CGO.

## Podpisywanie kodu

Wydania są podpisywane przez opiekuna. Zasady, weryfikacja podpisu i obsługa incydentów:
[CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).

## Bezpieczeństwo

Zgłaszanie podatności: [SECURITY.md](SECURITY.md). Model zagrożeń agenta: sekcja w
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Licencja

Kod: Apache License 2.0 ([LICENSE](LICENSE)). Nazwa „Piotr Melnyk IT - POMOC Zdalna”, logo i ikona nie są objęte
licencją, patrz [NOTICE](NOTICE). Zależności: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
