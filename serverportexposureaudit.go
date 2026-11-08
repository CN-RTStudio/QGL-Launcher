package main

import (
	"fmt"
	"sort"
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

type ServerPortFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerPortAudit struct {
	Dir      string
	File     string
	BindIP   string
	Ports    map[string]int
	Findings []ServerPortFinding
}

func (a ServerPortAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ServerPortFinding) bool { return f.Blocking })
}

func (a ServerPortAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != pxReasonOK {
			return true
		}
	}
	return false
}

func (a ServerPortAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == pxReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "server.properties"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= pxMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务端端口与绑定配置未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *ServerPortAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= pxMaxFindings {
		return
	}
	a.Findings = append(a.Findings, ServerPortFinding{
		File:     a.File,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}
