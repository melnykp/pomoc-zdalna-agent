// Package selfprotect utrudnia wyłączenie agenta na końcówce (docs/ARCHITECTURE.md):
// ACL na Program Files i ProgramData, recovery usług, wykrycie ręcznego zatrzymania.
//
// Zgodnie z planem nie udajemy, że lokalny administrator nie może nic zrobić:
// celem jest utrudnienie i widoczność (event.tamper), nie niezniszczalność.
//
// Stan: ACL katalogu danych i akcje odzyskiwania usług ustawia instalator (internal/svc). Ten pakiet jest jeszcze
// szkieletem. Planowane: wykrycie ręcznego zatrzymania usługi i zdarzenie event.tamper przy następnym połączeniu.
package selfprotect

import "context"

// Apply nakłada zabezpieczenia. W szkielecie nic nie robi i zwraca nil.
func Apply(ctx context.Context) error {
	return ctx.Err()
}
