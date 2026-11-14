package main

import ()

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
