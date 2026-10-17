# Współpraca

Zgłoszenia błędów i propozycje są mile widziane jako issues. Przed większą zmianą w kodzie napisz najpierw issue, bo agent
ma wąski zakres z założenia (bez wykonywania dowolnych poleceń) i część zmian będzie musiała zostać odrzucona.

Zasady zmian w kodzie:

- `gofmt`, `go vet ./...` i `go test ./...` muszą przechodzić (CI robi to samo).
- Każda zmiana w łańcuchu aktualizacji, handshake lub weryfikacji podpisów wymaga testu na prawdziwych plikach i opisu
  wpływu na bezpieczeństwo.
- Komentarze i komunikaty dla użytkownika po polsku, nazwy w kodzie po angielsku lub polsku zgodnie z otoczeniem.
- Wysyłając zmianę, zgadzasz się na jej udostępnienie na licencji Apache 2.0 (patrz `LICENSE`).
