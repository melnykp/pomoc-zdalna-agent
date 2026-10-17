# Zgłaszanie podatności

Jeśli znajdziesz błąd, który może narazić komputer albo dane użytkownika (omijanie weryfikacji podpisów aktualizacji,
podszycie się pod serwer lub urządzenie, podniesienie uprawnień przez agenta lub watchdoga, wyciek danych), nie zakładaj
publicznego zgłoszenia.

1. Użyj prywatnego zgłoszenia na GitHubie: karta **Security** → **Report a vulnerability** w tym repozytorium.
2. Jeśli to nie działa, skontaktuj się przez [melnyk.pl](https://melnyk.pl) i poproś o bezpieczny kanał.

Opisz, co zadziałało, na jakiej wersji agenta i systemu, oraz jak to powtórzyć. Odpowiadam najszybciej jak się da
(zwykle w ciągu kilku dni) i po poprawce wymieniam zgłaszającego, jeśli sobie tego życzy. Program nagród nie istnieje.

W zakresie są: agent, watchdog, łańcuch aktualizacji i protokół opisany w `docs/ARCHITECTURE.md`. Serwer i panel są
w osobnym, prywatnym repozytorium, ale błędy protokołu po jego stronie też proszę zgłaszać tutaj.
