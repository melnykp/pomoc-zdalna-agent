# Jakie dane zbiera agent

Agent wysyła dane wyłącznie do serwera, którego adres i klucz publiczny są wkompilowane w plik `agent.exe`. Połączenie
jest szyfrowane (TLS 1.3), a obie strony potwierdzają tożsamość podpisem (patrz [ARCHITECTURE.md](ARCHITECTURE.md)). Agent
nie korzysta z żadnych usług osób trzecich i nie ma telemetrii dla autora kodu.

## Co jest wysyłane

**Rejestracja (raz):** klucz publiczny urządzenia, nazwa komputera, rodzina i wersja systemu, architektura, skrót
identyfikujący sprzęt (SHA-256 z identyfikatora płyty i dysku, tylko do wykrywania duplikatów), wersja agenta.

**Stan (co 30 sekund):** użycie procesora, pamięci, czas działania, nazwa zalogowanego użytkownika, lokalne adresy IP, wersje
komponentów agenta.

**Inwentaryzacja (przy starcie, co kilka godzin i na polecenie):**
- system: nazwa, wersja, kompilacja, data instalacji, ostatnie uruchomienie;
- sprzęt: producent, model, numer seryjny, wersja BIOS, procesor, liczba rdzeni, pamięć, UUID płyty;
- dyski: litera, system plików, rozmiar i wolne miejsce;
- sieć: nazwa karty, adres MAC, adresy IP, czy DHCP;
- zainstalowane programy: nazwa, wersja, wydawca, data instalacji;
- zabezpieczenia: tylko status Windows Defender i BitLockera (włączony lub nie, bez treści).

**Wynik aktualizacji:** etap (pobieranie, zweryfikowano, zastosowano, wycofano), wersja z i do, treść błędu.

## Czego agent nie robi

- Nie czyta ani nie wysyła zawartości plików, historii przeglądarki, haseł, poczty ani wiadomości.
- Nie rejestruje klawiszy i nie przesyła obrazu ekranu. Zdalny pulpit jest osobnym, planowanym modułem, który uruchamia
  się tylko na polecenie inżyniera, z hasłem jednorazowym na sesję.
- Nie wykonuje dowolnych poleceń ani skryptów. Lista poleceń jest stała i opisana w
  [ARCHITECTURE.md](ARCHITECTURE.md).
- Logi lokalne (`logs`) nie zawierają treści ekranu ani sekretów.

## Gdzie to trafia i jak długo

Dane trafiają na serwer operatora usługi, czyli firmy, która wkompilowała w plik swój adres (w pliku rozprowadzanym przez
autora: Piotr Melnyk IT). Okres przechowywania i zasady powierzenia danych określa operator w umowie z klientem. Ten
projekt jest tylko oprogramowaniem po stronie komputera.

## Jak to zweryfikować

Kod zbierający dane jest w `internal/inventory`, `internal/metrics` i `internal/heartbeat`, a kształt wiadomości w
`pkg/wire`. Logi agenta: `C:\ProgramData\Piotr Melnyk IT - POMOC Zdalna\logs\agent.log`.
