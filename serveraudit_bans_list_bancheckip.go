package main

import (
	"net"
	"strings"
)

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

func (a BanListAudit) Codes() []string {
	return findingCodesSkip(a.Findings, banReasonOK, func(f BanFinding) string { return f.Reason })
}
