package remote

import (
	"strings"
	"testing"
)

func TestGenerateOTP(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 500; i++ {
		otp, err := GenerateOTP(OTPLength)
		if err != nil {
			t.Fatal(err)
		}
		if len(otp) != OTPLength {
			t.Fatalf("zła długość: %d", len(otp))
		}
		for _, c := range otp {
			if !strings.ContainsRune(otpAlphabet, c) {
				t.Fatalf("znak poza alfabetem: %q", c)
			}
		}
		if strings.ContainsAny(otp, "0O1lI") {
			t.Fatalf("hasło zawiera mylące znaki: %s", otp)
		}
		if _, dup := seen[otp]; dup {
			t.Fatal("powtórzone hasło")
		}
		seen[otp] = struct{}{}
	}
}

func TestLockPasswordIsLonger(t *testing.T) {
	lock, err := LockPassword()
	if err != nil || len(lock) <= OTPLength {
		t.Fatalf("hasło zamykające powinno być dłuższe niż OTP: %q %v", lock, err)
	}
}
