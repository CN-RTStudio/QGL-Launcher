package main

import (
	"net/url"
	"strings"
)

func mappingsURLAllowed(raw string) bool {
	if raw == "" || len(raw) > 2048 {
		return false
	}
	if strings.ContainsAny(raw, "'\"`$;|&<>\r\n\t ") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "piston-data.mojang.com", "launcher.mojang.com", "bmclapi2.bangbang93.com":
	default:
		return false
	}
	return u.Path != "" && !strings.Contains(u.Path, "..")
}
