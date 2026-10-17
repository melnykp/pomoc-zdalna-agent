package releasesig

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrBadVersion oznacza wersję w złym formacie (oczekiwano MAJOR.MINOR.PATCH z opcjonalnym -przyrostkiem).
var ErrBadVersion = errors.New("releasesig: zła wersja")

type semver struct {
	major, minor, patch uint64
	pre                 []string // identyfikatory przyrostka po myślniku
}

func parseSemver(v string) (semver, error) {
	core, pre, hasPre := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("%w: %q", ErrBadVersion, v)
	}
	var nums [3]uint64
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return semver{}, fmt.Errorf("%w: %q", ErrBadVersion, v)
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return semver{}, fmt.Errorf("%w: %q", ErrBadVersion, v)
		}
		nums[i] = n
	}
	s := semver{major: nums[0], minor: nums[1], patch: nums[2]}
	if hasPre {
		if pre == "" {
			return semver{}, fmt.Errorf("%w: %q", ErrBadVersion, v)
		}
		for _, id := range strings.Split(pre, ".") {
			if id == "" {
				return semver{}, fmt.Errorf("%w: %q", ErrBadVersion, v)
			}
			s.pre = append(s.pre, id)
		}
	}
	return s, nil
}

// CompareVersions porównuje dwie wersje semver: -1, 0 albo 1. Przyrostek (np. -rc1) oznacza wersję niższą od
// takiej samej bez przyrostka, a identyfikatory przyrostka porównujemy liczbowo, gdy są liczbami, inaczej tekstowo.
func CompareVersions(a, b string) (int, error) {
	x, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	y, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	for _, p := range [][2]uint64{{x.major, y.major}, {x.minor, y.minor}, {x.patch, y.patch}} {
		if p[0] != p[1] {
			if p[0] < p[1] {
				return -1, nil
			}
			return 1, nil
		}
	}
	switch {
	case len(x.pre) == 0 && len(y.pre) == 0:
		return 0, nil
	case len(x.pre) == 0:
		return 1, nil
	case len(y.pre) == 0:
		return -1, nil
	}
	for i := 0; i < len(x.pre) && i < len(y.pre); i++ {
		if c := compareIdent(x.pre[i], y.pre[i]); c != 0 {
			return c, nil
		}
	}
	switch {
	case len(x.pre) < len(y.pre):
		return -1, nil
	case len(x.pre) > len(y.pre):
		return 1, nil
	}
	return 0, nil
}

func compareIdent(a, b string) int {
	na, ea := strconv.ParseUint(a, 10, 64)
	nb, eb := strconv.ParseUint(b, 10, 64)
	switch {
	case ea == nil && eb == nil:
		switch {
		case na < nb:
			return -1
		case na > nb:
			return 1
		}
		return 0
	case ea == nil: // liczby są niższe od tekstu
		return -1
	case eb == nil:
		return 1
	}
	return strings.Compare(a, b)
}
