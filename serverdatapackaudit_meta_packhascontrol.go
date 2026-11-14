package main

import ()

func packHasControl(value string) bool {
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch < 0x20 && ch != '\t' && ch != '\n' {
			return true
		}
		if ch == 0x7f {
			return true
		}
	}
	return false
}
