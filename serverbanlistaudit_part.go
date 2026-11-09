package main

import (
	"net"
	"strings"
	"time"
)

func banParseExpiry(value string) (time.Time, bool) {
	text := strings.TrimSpace(value)
	if text == "" {
		return time.Time{}, true
	}
	if strings.EqualFold(text, "forever") {
		return time.Time{}, true
	}
	layouts := []string{"2006-01-02 15:04:05 -0700", "2006-01-02 15:04:05 -07:00", time.RFC3339}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, text); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func banCheckIP(entry banEntry) (reason string, blocking bool) {
	ip := strings.TrimSpace(entry.IP)
	if ip == "" {
		return banReasonBadIP, true
	}
	if ip == "*" {
		return banReasonWildcard, true
	}
	if strings.Contains(ip, "/") {
		_, network, err := net.ParseCIDR(ip)
		if err != nil || network == nil {
			return banReasonBadIP, true
		}
		ones, bits := network.Mask.Size()
		if bits == 32 && ones <= 8 {
			return banReasonBroadCIDR, true
		}
		if bits == 128 && ones <= 16 {
			return banReasonBroadCIDR, true
		}
		return "", false
	}
	if net.ParseIP(ip) == nil {
		return banReasonBadIP, true
	}
	return "", false
}

func banTextSane(value string) bool {
	if len(value) > 512 {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch < 0x20 && ch != '\t' {
			return false
		}
		if ch == 0x7f {
			return false
		}
	}
	return true
}
