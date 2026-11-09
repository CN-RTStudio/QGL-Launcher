package main

import "strings"

const maxServerOutputLineChars = 16 * 1024

func stripControlSequences(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	out := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x1b {
			i++
			if i >= len(s) {
				break
			}
			switch s[i] {
			case '[':
				i++
				for i < len(s) {
					f := s[i]
					if f >= 0x40 && f <= 0x7e {
						break
					}
					i++
				}
			case ']', 'P', '^', '_', 'X':
				i++
				for i < len(s) {
					if s[i] == 0x07 {
						break
					}
					if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
						i++
						break
					}
					i++
				}
			default:
			}
			continue
		}
		if c < 0x20 || c == 0x7f {
			if c == '\t' {
				b.WriteByte(c)
				out++
			}
			continue
		}
		if out >= maxServerOutputLineChars {
			break
		}
		b.WriteByte(c)
		out++
	}
	return b.String()
}
