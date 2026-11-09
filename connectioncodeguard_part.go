package main

import "strconv"

func encodePrefix(firstSeg int) (string, bool) {
	if firstSeg < 0 || firstSeg > 255 {
		return "", false
	}
	switch firstSeg {
	case 10:
		return "A", true
	case 172:
		return "B", true
	case 192:
		return "C", true
	case 1:
		return "D", true
	default:
		return "X" + strconv.Itoa(firstSeg), true
	}
}

// parseHexSegment 解析单个十六进制 IP 段，要求非空、纯十六进制、取值 0-255。
func parseHexSegment(token string) (int, bool) {
	if token == "" {
		return 0, false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(token, 16, 0)
	if err != nil || n < 0 || n > 255 {
		return 0, false
	}
	return int(n), true
}
