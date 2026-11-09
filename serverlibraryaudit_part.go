package main

import (
	"os"
)

func libLooksVersion(segment string) bool {
	digits, alpha := 0, 0
	for i := 0; i < len(segment); i++ {
		ch := segment[i]
		if ch >= '0' && ch <= '9' {
			digits++
			continue
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			alpha++
		}
	}
	if digits == 0 {
		return false
	}
	return digits >= alpha
}

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

func libLooksLikeZip(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 4)
	n, err := f.Read(head)
	if err != nil && n < 4 {
		return false
	}
	return string(head) == "PK\x03\x04" || string(head) == "PK\x05\x06"
}
