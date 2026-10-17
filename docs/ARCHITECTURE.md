# Architektura agenta

Ten dokument opisuje, jak działa agent, jakim protokołem rozmawia z serwerem i jak się aktualizuje. Dotyczy kodu w tym
repozytorium. Serwer i panel są osobnymi projektami i nie są tu opisane poza granicą protokołu.

## 1. Procesy i pliki na komputerze

Jeden plik `agent.exe` pełni dwie role, wybierane poleceniem: `service` (agent) i `watchdog-service` (nadzorca). Instalator
kopiuje go jako `agent.exe` i `watchdog.exe` i zakłada dwie usługi Windows (konto LocalSystem, start automatyczny, restart
po awarii). Jeden plik oznacza jeden artefakt do podpisania i brak macierzy zgodności dwóch binarek.

```
C:\Program Files\Piotr Melnyk IT - POMOC Zdalna\
  agent.exe, watchdog.exe     usługi PomocZdalnaAgent i PomocZdalnaWatchdog
  *.prev                      poprzednia wersja do powrotu (rollback)
C:\ProgramData\Piotr Melnyk IT - POMOC Zdalna\      (dostęp tylko SYSTEM i Administratorzy)
  config.json                 adres serwera, device_id, interwały
  identity.bin                klucz prywatny urządzenia (Ed25519)
  state\                      prośby o podmianę i ich wyniki, próg bezpieczeństwa, znaczniki zdrowia, odrzucone wydania
  staging\                    pobrane i zweryfikowane pliki aktualizacji
  logs\                       agent.log, watchdog.log (JSON, rotacja)
```

Katalog danych ma ACL ograniczone do SYSTEM i Administratorów, a właścicielem są Administratorzy (`internal/svc`). Instalator
nie ufa katalogowi, który istniał przed instalacją, jeśli należy do kogoś innego lub jest dowiązaniem: odkłada go na bok
i zakłada nowy. Klucz prywatny urządzenia jest szyfrowany DPAPI w zakresie maszyny (plik z przedrostkiem `PMZ1:`), więc kopia
pliku nie działa na innym komputerze. Stary plik ze zwykłym tekstem jest przy pierwszym odczycie przepisywany.

## 2. Moduły

| Pakiet | Zadanie |
|---|---|
| `cmd/agent` | punkt wejścia: tryby `service`, `watchdog-service`, `install`, `uninstall`, `version` |
| `internal/installer` | instalacja: uprawnienia administratora (UAC), kopia plików, usługi, rejestracja, okno z kodem kontrolnym |
| `internal/enroll` | rejestracja urządzenia na serwerze z jednorazowego zaproszenia |
| `internal/config`, `internal/identity` | konfiguracja i tożsamość urządzenia (para kluczy Ed25519) |
| `internal/transport`, `internal/session`, `internal/protocol` | kanał WSS, handshake i koperta wiadomości |
| `internal/runner` | pętla główna: połączenie, stan, polecenia, aktualizacje |
| `internal/heartbeat`, `internal/metrics`, `internal/inventory` | zbieranie stanu i inwentaryzacji |
| `internal/commands` | odbiór i wykonanie poleceń z listy stałej, idempotencja po `command_id` |
| `internal/update`, `pkg/releasesig` | weryfikacja i pobieranie aktualizacji, podpisy manifestów |
| `internal/watchdog` | podmiana plików, rollback, pętla awarii |
| `internal/svc` | usługi Windows, akcje odzyskiwania usług, ACL katalogu danych |
| `internal/selfprotect` | szkielet: planowane wykrywanie ręcznego zatrzymania usługi |
| `internal/remote` | szkielet modułu zdalnego pulpitu (planowany, jeszcze bez pulpitu) |

## 3. Rejestracja

1. Plik instalatora zna zaproszenie: z nazwy pliku, z adresu pobrania zapisanego przy pliku przez przeglądarkę
   (strumień `Zone.Identifier`) albo z opcji `--token`.
2. `POST /v1/enroll` z kluczem publicznym urządzenia i podstawowymi danymi komputera.
3. Serwer odpowiada identyfikatorem urządzenia i statusem (`pending` lub `approved`). Dopóki komputer nie jest
   zatwierdzony przez inżyniera, agent ponawia połączenie rzadko.
4. Klucze serwera są wkompilowane w agenta i są nadrzędne. Lista z odpowiedzi jest tylko informacyjna.

## 4. Protokół v1 (WSS, ramki tekstowe JSON)

Koperta: `{ "v": 1, "t": "<typ>", "id": "<ULID>", "ts": <ms>, "re": "<id wiadomości, na którą to odpowiedź>", "d": { ... } }`.
Typy i kształty danych: `pkg/wire`.

**Handshake (uwierzytelnienie wzajemne):**

```
agent  → połączenie WSS (nagłówek X-Device-Id)
serwer → hello    { server_nonce, server_key_id, protocol_versions, time }
agent  → auth     { device_id, agent_nonce, wersje, caps,
                    sig = Ed25519(klucz urządzenia, "rmm-auth-v1" || server_nonce || agent_nonce || device_id) }
serwer → auth.ok  { session_id, heartbeat_s, inventory_h, time,
                    sig = Ed25519(klucz serwera, "rmm-srv-v1" || agent_nonce || server_nonce || device_id) }
        | auth.fail { reason: pending | blocked | retired | bad_signature | unknown_device }
```

Agent sprawdza podpis serwera kluczem wkompilowanym o wskazanym `server_key_id`. Podszycie się pod serwer (DNS, MITM)
nie wystarczy bez klucza prywatnego serwera. TLS 1.3 jest minimum.

**Agent → serwer:** `hb` (stan co `heartbeat_s`, domyślnie 30 s), `inventory.full`, `cmd.ack`, `cmd.result`,
`update.status`, a w planowanym module pulpitu `remote.otp` i `remote.state`. Wiadomość `event` (zdarzenia lokalne, np.
`tamper`, `crash_loop`) jest zdefiniowana w `pkg/wire`, ale agent jeszcze jej nie wysyła.

**Serwer → agent:** `cmd`, `cmd.result.ack`, `release.available`, `auth.retry`.

**Polecenia (`cmd.type`), lista stała:** `inventory.refresh`, `update.check`, `update.apply`, `agent.restart`,
`config.set` (interwały), `device.retire` (usunięcie agenta), a w przyszłym module pulpitu `remote.open` i `remote.close`.
Nieznany typ jest odrzucany. Agent nie ma polecenia wykonującego dowolny program ani skrypt.

**Niezawodność:** polecenia są dostarczane co najmniej raz (serwer ponawia po braku `cmd.ack`), agent deduplikuje po
`command_id` (pamięć ostatnich 1000 identyfikatorów, w procesie). Trwała kolejka wyników na dysku jest planowana. Połączenie
jest ponawiane z narastającym opóźnieniem i losowym rozrzutem. Ramka ma limit rozmiaru (inwentaryzacja większy).

## 5. Aktualizacje

Źródłem prawdy o wydaniu jest podpisany **manifest** (`pkg/releasesig`):

```json
{
  "schema": 1, "component": "agent", "version": "1.3.0", "os": "windows", "arch": "amd64",
  "artifact": { "url": "https://serwer/v1/releases/artifacts/...", "sha256": "<64 hex>", "size": 9437184 },
  "requires": { "watchdog_min": "1.0.0" },
  "min_version": "1.2.0",
  "authenticode_subject": "CN=..., O=..., C=PL",
  "released_at": "2026-11-20T10:00:00Z"
}
```

Manifest jest podpisany poza serwerem i poza CI: `ssh-keygen -Y sign -n rmm-release` (format `sshsig`, klucz
`ssh-ed25519` albo `sk-ssh-ed25519` na kluczu sprzętowym z dotknięciem). Agent ma wkompilowaną listę zaufanych kluczy
podpisu wydań. Serwer jedynie przekazuje manifest i podpis, więc przejęcie serwera nie pozwala rozesłać własnej wersji.

Agent przyjmuje plik tylko, gdy **wszystko** przejdzie:

1. podpis `sshsig` manifestu ważny, klucz na liście zaufanych, przestrzeń nazw `rmm-release`;
2. komponent, system i architektura zgodne, wersja **wyższa** od uruchomionej. Agent nigdy nie cofa się do starszego wydania:
   wycofanie wadliwego wydania to nowe wydanie z wyższym numerem;
3. po pobraniu SHA-256 i rozmiar zgodne z manifestem (sprawdzane w trakcie strumienia, z limitem rozmiaru);
4. ważny podpis Authenticode ze znacznikiem czasu, a podmiot certyfikatu zgodny z `authenticode_subject`
   i z podmiotem działającego pliku;
5. wersja nie jest niższa od zapamiętanego **progu bezpieczeństwa** (`min_version`), żeby przejęty serwer nie
   cofnął agenta do poprawnie podpisanej, ale podatnej wersji.

**Podmiana:** agent zapisuje zweryfikowany plik w `staging` i prośbę o podmianę w `state`, dołączając do niej manifest i podpis
sshsig dokładnie tak, jak je dostał. Watchdog nie ufa prośbie: sam weryfikuje podpis manifestu kluczami wkompilowanymi w plik
(bez nich odmawia każdej podmiany), sprawdza zgodność prośby z manifestem, że ścieżka leży w `staging`, a rozmiar, SHA-256
i Authenticode bierze z manifestu. Ktoś, kto zdoła zapisać prośbę w katalogu stanu, nie podstawi więc własnego pliku bez klucza
wydań. Dopiero wtedy watchdog zatrzymuje agenta, zapisuje poprzednią wersję jako `.prev` i podmienia plik.

**Zdrowie i rollback:** nowa wersja jest zdrowa, gdy zrobiła handshake z serwerem i wysłała heartbeat. Jeśli w ciągu
2 minut tego nie zrobi, a serwer jest osiągalny z komputera, watchdog wraca do `.prev` i oznacza wydanie jako odrzucone.
Gdy komputer jest bez internetu, nowa wersja zostaje, bo nic nie wskazuje na jej winę. Trzy starty w 10 minut po
aktualizacji też kończą się powrotem. Odrzucone wydania są zapamiętywane i nie są ponawiane w pętli.

## 6. Model zagrożeń agenta (skrót)

| Zagrożenie | Kontrola |
|---|---|
| Podszycie się pod serwer | TLS 1.3 oraz podpis serwera kluczem wkompilowanym w agenta |
| Podszycie się pod urządzenie | klucz Ed25519 per urządzenie, jedna sesja na urządzenie |
| Fałszywa lub cofnięta aktualizacja | podpis manifestu poza serwerem, SHA-256, Authenticode, próg `min_version`, ponowna weryfikacja przez watchdoga, rollback |
| Złośliwe polecenie z przejętego serwera | lista poleceń stała i niegroźna, brak wykonywania dowolnego kodu |
| Zwykły użytkownik komputera przygotowuje katalog danych przed instalacją | instalator odkłada na bok katalog z obcym właścicielem lub dowiązaniem i zakłada własny, a watchdog i tak weryfikuje podpisany manifest |
| Lokalny administrator manipuluje agentem | ACL katalogu danych i akcje odzyskiwania usług; wykrywanie ręcznego zatrzymania jest planowane. Całkowicie nie da się tego uniemożliwić administratorowi |
| Wyciek danych | agent wysyła tylko dane z [PRIVACY.md](PRIVACY.md), wyłącznie do wkompilowanego serwera |

Zgłaszanie podatności: [SECURITY.md](../SECURITY.md).

## 7. Parametry kompilacji (`-ldflags -X`)

| Zmienna | Cel |
|---|---|
| `main.version` | wersja agenta |
| `main.defaultServer` | adres bramki agenta (instalator z linku nie pyta o serwer) |
| `<moduł>/internal/trust.Compiled` | zaufane klucze serwera `id=base64` rozdzielone przecinkami |
| `<moduł>/pkg/releasesig.CompiledSigners` | zaufane klucze podpisu wydań (format `authorized_keys`) |
| `<moduł>/internal/update.RequireAuthenticode` | `false` tylko w rozwoju i testach |
| `<moduł>/internal/update.AuthenticodeSubjectPin` | podmiot certyfikatu producenta: aktualizacje muszą być podpisane właśnie nim, niezależnie od manifestu |

`<moduł>` to ścieżka modułu z `go.mod`. Skrypt `build/build.ps1` składa te opcje z parametrów.
