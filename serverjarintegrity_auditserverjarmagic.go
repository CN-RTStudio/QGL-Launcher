package main

import (
	"strings"
)

func auditServerJarMagic(header, tail []byte) (bool, bool) {
	zipHeader := len(header) >= serverJarHeaderBytes &&
		header[0] == 'P' && header[1] == 'K' && header[2] == 3 && header[3] == 4
	zipCentral := false
	for i := len(tail) - 22; i >= 0; i-- {
		if tail[i] == 'P' && tail[i+1] == 'K' && tail[i+2] == 5 && tail[i+3] == 6 {
			zipCentral = true
			break
		}
	}
	return zipHeader, zipCentral
}

func suspiciousServerJarEntry(name string) bool {
	if name == "" {
		return true
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
		return true
	}
	if strings.Contains(name, "\\") {
		return true
	}
	if len(name) >= 2 && name[1] == ':' {
		return true
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}
