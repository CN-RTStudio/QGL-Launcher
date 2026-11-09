package main

import (
	"strconv"
)

// ServerListLimits 限定服务器地址与名称的输入边界。
type ServerListLimits struct {
	MaxHostRunes int
	MaxNameRunes int
	MaxPort      int
	MaxLines     int
	MaxLineRunes int
}

func serverFormatRune(r rune) bool {
	if r < 0x20 || r == 0x7f {
		return true
	}
	if r >= 0x80 && r <= 0x9f {
		return true
	}
	if r >= 0x202a && r <= 0x202e {
		return true
	}
	if r >= 0x2066 && r <= 0x2069 {
		return true
	}
	switch r {
	case 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2028, 0x2029, 0xfeff:
		return true
	}
	return false
}

func parseServerPort(raw string, max int) (int, bool) {
	if raw == "" {
		return 0, false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 || v > max {
		return 0, false
	}
	return v, true
}
