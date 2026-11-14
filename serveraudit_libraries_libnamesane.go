package main

import ()

func libNameSane(name string) bool {
	if name == "" || len(name) > 160 {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if ch < 0x20 || ch == 0x7f {
			return false
		}
	}
	return true
}
