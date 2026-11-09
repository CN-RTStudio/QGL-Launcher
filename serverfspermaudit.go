package main

import (
	"fmt"
	"strings"
)

const (
	fsPermReasonOK            = "ok"
	fsPermReasonMissing       = "missing"
	fsPermReasonSymlink       = "symlink"
	fsPermReasonNotRegular    = "not-regular"
	fsPermReasonUnreadable    = "unreadable"
	fsPermReasonWorldWritable = "world-writable"
	fsPermReasonGroupWritable = "group-writable"
	fsPermReasonWorldReadable = "secret-world-readable"
	fsPermReasonExecutable    = "executable-config"
	fsPermReasonSpecialBit    = "special-bit"
	fsPermReasonPlatform      = "unsupported-platform"
)

type FSPermFinding struct {
	Path     string
	Mode     string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerFSPermAudit struct {
	Dir      string
	Checked  []string
	Findings []FSPermFinding
}

func (a *ServerFSPermAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f FSPermFinding) bool { return f.Blocking })
}

func (a *ServerFSPermAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f FSPermFinding) bool {
		return !f.Blocking && f.Reason != fsPermReasonOK && f.Reason != fsPermReasonMissing && f.Reason != fsPermReasonPlatform
	})
}

func (a *ServerFSPermAudit) Codes() []string {
	return findingCodes(a.Findings, func(f FSPermFinding) string { return f.Reason })
}

func (a *ServerFSPermAudit) Describe() string {
	if a == nil || len(a.Findings) == 0 {
		return "服务器文件权限审计: 未发现敏感路径"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == fsPermReasonOK || f.Reason == fsPermReasonMissing || f.Reason == fsPermReasonPlatform {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s(%s) %s %s", f.Path, f.Mode, f.Reason, f.Detail))
	}
	if len(parts) == 0 {
		return "服务器文件权限审计: 通过"
	}
	return strings.Join(parts, "; ")
}

func (a *ServerFSPermAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f FSPermFinding) bool { return f.Blocking }, func(f FSPermFinding) bool {
		return !f.Blocking && f.Reason != fsPermReasonOK && f.Reason != fsPermReasonMissing && f.Reason != fsPermReasonPlatform
	})
	return fmt.Sprintf("权限审计 %d 个路径，阻断 %d，告警 %d", len(a.Checked), blocking, warnings)
}

type fsPermTarget struct {
	Path       string
	Kind       string
	Secret     bool
	BlockWrite bool
	ExpectDir  bool
}

func serverFSPermTargets() []fsPermTarget {
	return []fsPermTarget{
		{Path: ".", Kind: "dir", BlockWrite: false, ExpectDir: true},
		{Path: "server.properties", Kind: "config", Secret: true, BlockWrite: true},
		{Path: "eula.txt", Kind: "config", BlockWrite: false},
		{Path: "ops.json", Kind: "config", Secret: true, BlockWrite: true},
		{Path: "whitelist.json", Kind: "config", Secret: true, BlockWrite: true},
		{Path: "banned-players.json", Kind: "config", BlockWrite: true},
		{Path: "banned-ips.json", Kind: "config", BlockWrite: true},
		{Path: "forwarding.secret", Kind: "secret", Secret: true, BlockWrite: true},
		{Path: "plugins", Kind: "dir", BlockWrite: true, ExpectDir: true},
		{Path: "logs", Kind: "dir", BlockWrite: false, ExpectDir: true},
		{Path: "world", Kind: "dir", BlockWrite: true, ExpectDir: true},
		{Path: "world/level.dat", Kind: "data", BlockWrite: true},
		{Path: "world/session.lock", Kind: "data", BlockWrite: false},
	}
}
