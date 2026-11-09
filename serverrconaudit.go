package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	rconReasonOK             = "ok"
	rconReasonMissing        = "missing"
	rconReasonSymlink        = "symlink"
	rconReasonUnreadable     = "unreadable"
	rconReasonEmptyPassword  = "empty-rcon-password"
	rconReasonWeakPassword   = "weak-rcon-password"
	rconReasonBadPassword    = "bad-rcon-password"
	rconReasonBadPort        = "bad-rcon-port"
	rconReasonPortCollision  = "rcon-port-collision"
	rconReasonBroadcast      = "rcon-broadcast-to-ops"
	rconReasonQueryEnabled   = "query-enabled"
	rconReasonQueryPublic    = "query-public"
	rconReasonQueryPort      = "bad-query-port"
	rconReasonQueryCollision = "query-port-collision"
	rconReasonStalePassword  = "stale-rcon-password"
	rconReasonDuplicateKey   = "duplicate-key"
	rconMinPasswordRunes     = 8
	rconMaxPasswordRunes     = 256
)

type RconFinding struct {
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerRconAudit struct {
	Path     string
	Present  bool
	Findings []RconFinding
}

func (a *ServerRconAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f RconFinding) bool { return f.Blocking })
}

func (a *ServerRconAudit) HasWarnings() bool {
	if a == nil {
		return false
	}
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != rconReasonOK {
			return true
		}
	}
	return false
}

func (a *ServerRconAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodes(a.Findings, func(f RconFinding) string { return f.Reason })
}

func (a *ServerRconAudit) Describe() string {
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Key == "" {
			parts = append(parts, fmt.Sprintf("%s: %s", f.Reason, f.Detail))
			continue
		}
		if f.Value != "" {
			parts = append(parts, fmt.Sprintf("%s=%q(%s): %s", f.Key, f.Value, f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s(%s): %s", f.Key, f.Reason, f.Detail))
	}
	return strings.Join(parts, "；")
}

func AuditServerRcon(serverDir string) (*ServerRconAudit, error) {
	path := filepath.Join(serverDir, "server.properties")
	audit := &ServerRconAudit{Path: path}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			audit.Findings = append(audit.Findings, RconFinding{
				Reason: rconReasonMissing, Detail: "server.properties 不存在，无法审计 RCON/Query 暴露面",
			})
			return audit, nil
		}
		return nil, fmt.Errorf("读取 server.properties 属性失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, RconFinding{
			Reason: rconReasonSymlink, Detail: "server.properties 是符号链接", Blocking: true,
		})
		return audit, nil
	}
	if !info.Mode().IsRegular() {
		audit.Findings = append(audit.Findings, RconFinding{
			Reason: rconReasonUnreadable, Detail: "server.properties 不是普通文件", Blocking: true,
		})
		return audit, nil
	}
	if info.Size() > int64(localTextConfigMaxBytes) {
		audit.Findings = append(audit.Findings, RconFinding{
			Reason: rconReasonUnreadable, Detail: "server.properties 体积异常，跳过审计", Blocking: true,
		})
		return audit, nil
	}
	data, err := readBoundedFile(path, int64(localTextConfigMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("读取 server.properties 失败: %w", err)
	}
	props := parseServerProperties(data)
	audit.Present = true
	audit.auditDuplicateKeys(props)
	audit.auditRcon(props)
	audit.auditQuery(props)
	return audit, nil
}
