package main

import (
	"net"
	"strings"
)

const maxBrowserURLLen = 4096

type BrowserURLError struct {
	Code   string
	Detail string
}

func (e *BrowserURLError) Error() string {
	if e == nil {
		return ""
	}
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}
func browserURLError(code, detail string) *BrowserURLError {
	return &BrowserURLError{Code: code, Detail: detail}
}
func isPrivateOrLocalIP(ip net.IP) bool {
	return isNonPublicIP(ip)
}
func ipLiteralFromHost(host string) (net.IP, bool) {
	h := strings.TrimPrefix(host, "[")
	h = strings.TrimSuffix(h, "]")
	if h == "" {
		return nil, false
	}
	return parseDestIP(h)
}
