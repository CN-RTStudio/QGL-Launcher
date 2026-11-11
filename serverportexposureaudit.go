package main

import (
	"strconv"
	"strings"
)

const (
	pxReasonOK            = "ok"
	pxReasonMissing       = "missing"
	pxReasonUnreadable    = "unreadable"
	pxReasonSymlink       = "symlink"
	pxReasonBadPort       = "bad-port"
	pxReasonPortConflict  = "port-conflict"
	pxReasonBindAll       = "bind-all-interfaces"
	pxReasonLowPort       = "privileged-port"
	pxReasonRconOpen      = "rcon-without-password"
	pxReasonWeakPassword  = "weak-rcon-password"
	pxReasonStaleSecret   = "stale-rcon-password"
	pxReasonRconExposed   = "rcon-all-interfaces"
	pxReasonQueryOpen     = "query-without-limit"
	pxReasonProxyBypass   = "proxy-bypass-off"
	pxReasonTooLarge      = "too-large"
	pxReasonWorldWritable = "world-writable"

	pxMaxPropertiesBytes = 1 << 20
	pxMaxFindings        = 64
	pxMinPasswordLength  = 8
)

var pxWeakPasswords = []string{
	"rcon",
	"password",
	"changeme",
	"minecraft",
	"admin",
	"123456",
	"12345678",
	"letmein",
	"secret",
	"test",
}

var pxForbiddenPorts = map[int]string{
	25:    "smtp",
	135:   "msrpc",
	139:   "netbios",
	445:   "smb",
	1433:  "mssql",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgres",
	6379:  "redis",
	8080:  "http-proxy",
	27017: "mongodb",
}

func pxParseProperties(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		out[strings.ToLower(key)] = value
	}
	return out
}
func pxParsePort(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	if len(value) > 1 && value[0] == '0' {
		return 0, false
	}
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	if port < 1 || port > 65535 {
		return port, false
	}
	return port, true
}

func pxIsBindAll(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if value == "0.0.0.0" || value == "::" || value == "[::]" || value == "*" {
		return true
	}
	return false
}
