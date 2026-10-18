//go:build windows

package remote

import "golang.org/x/sys/windows/registry"

// uacDisabled mówi, czy kontrola konta użytkownika jest wyłączona całkiem (EnableLUA=0 w polityce systemu). Wtedy nie ma tokenu filtrowanego i
// okna administratora nie mają osobnej, wyższej integralności, więc poziom „user” niczego przed nimi nie chroni, a prośba o zgodę nie ma sensu.
// Brak wartości albo błąd odczytu to UAC włączony (domyślne ustawienie Windows).
func uacDisabled() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("EnableLUA")
	return err == nil && v == 0
}
