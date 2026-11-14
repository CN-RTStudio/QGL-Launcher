package main

import (
	"os"
)

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
