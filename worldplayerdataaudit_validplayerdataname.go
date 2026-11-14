package main

import (
	"strings"
)

func validPlayerDataName(dir, name string) bool {
	lower := strings.ToLower(name)
	switch dir {
	case "playerdata":
		stem := strings.TrimSuffix(lower, ".dat")
		stem = strings.TrimSuffix(stem, ".dat_old")
		if stem == lower {
			return false
		}
		if len(stem) != 32 || !IsLowerHex(stem, 32) {
			if len(stem) == 36 {
				return validDashedUUID(stem)
			}
			return false
		}
		return true
	case "stats", "advancements":
		if !strings.HasSuffix(lower, ".json") {
			return false
		}
		stem := strings.TrimSuffix(lower, ".json")
		if len(stem) == 32 && IsLowerHex(stem, 32) {
			return true
		}
		if len(stem) == 36 {
			return validDashedUUID(stem)
		}
		return false
	}
	return true
}

func validDashedUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, ch := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}
