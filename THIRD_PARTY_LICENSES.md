# Zależności zewnętrzne

Agent korzysta z biblioteki standardowej Go i czterech modułów. Pełne teksty licencji są w kodzie modułów
(`go mod download`, katalog modułu, plik `LICENSE`).

| Moduł | Licencja | Do czego |
|---|---|---|
| `github.com/coder/websocket` | ISC | klient WebSocket do połączenia z serwerem |
| `github.com/hiddeco/sshsig` | Apache-2.0 | weryfikacja podpisów manifestów wydań (format sshsig) |
| `golang.org/x/crypto` | BSD-3-Clause | obsługa kluczy SSH (weryfikacja podpisów wydań) |
| `golang.org/x/sys` | BSD-3-Clause | usługi Windows, ACL, WinVerifyTrust, rejestr |

Narzędzie `github.com/josephspurrier/goversioninfo` (MIT) jest używane tylko przy budowaniu pliku `.exe` (zasoby, ikona)
i nie trafia do programu.
