package main

func uniquifyModName(existing []string, desired string) (string, bool, bool) {
	if _, hit := findModNameCollision(existing, desired); !hit {
		return desired, false, true
	}
	occupied := make(map[string]bool, len(existing)+8)
	for _, n := range existing {
		if k := modNameCollisionKey(n); k != "" {
			occupied[k] = true
		}
	}
	stem, ext := splitModStemExt(desired)
	for n := 2; n <= maxModNameUniquifyAttempts; n++ {
		candidate := stem + " (" + itoaModName(n) + ")" + ext
		key := modNameCollisionKey(candidate)
		if key != "" && !occupied[key] {
			return candidate, true, true
		}
		occupied[key] = true
	}
	return "", true, false
}
func itoaModName(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
