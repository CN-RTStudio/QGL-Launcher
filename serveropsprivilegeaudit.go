package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	syoMaxFile     = 512 * 1024
	syoMaxFindings = 20
	syoMaxOps      = 64
	syoMaxLevel    = 4
	syoMissing     = "ops-file-missing"
	syoUnreadable  = "ops-file-unreadable"
	syoSymlink     = "ops-file-symlink"
	syoBadJSON     = "ops-json-invalid"
	syoEmpty       = "ops-entry-empty"
	syoOfflineUUID = "ops-offline-uuid"
	syoBadUUID     = "ops-uuid-malformed"
	syoOverLevel   = "ops-level-too-high"
	syoBadLevel    = "ops-level-missing"
	syoDuplicate   = "ops-duplicate-uuid"
	syoTooMany     = "ops-entry-limit"
	syoByName      = "ops-name-underspecified"
	syoBypass      = "ops-bypass-enabled"
)

type OpsEntry struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Level   int    `json:"level"`
	Bypass  bool   `json:"bypassesPlayerLimit"`
	Banned  bool   `json:"-"`
	HasName bool   `json:"-"`
}

type OpsPrivilegeFinding struct {
	Reason   string
	Detail   string
	Blocking bool
}

type OpsPrivilegeAudit struct {
	ServerDir string
	Entries   int
	Findings  []OpsPrivilegeFinding
}

func (a *OpsPrivilegeAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, syoMaxFindings, OpsPrivilegeFinding{Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *OpsPrivilegeAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f OpsPrivilegeFinding) bool { return f.Blocking })
}

func (a *OpsPrivilegeAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *OpsPrivilegeAudit) Describe() string {
	return describeAuditFindings("运维权限配置未发现风险", a.Findings, 10,
		func(f OpsPrivilegeFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f OpsPrivilegeFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func syoUUIDShape(uuid string) string {
	clean := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(uuid)), "-", "")
	if len(clean) != 32 {
		return syoBadUUID
	}
	for _, r := range clean {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return syoBadUUID
		}
	}
	if clean[12] == '3' && strings.ContainsRune("89ab", rune(clean[16])) {
		return syoOfflineUUID
	}
	return ""
}

func syoParse(data []byte, a *OpsPrivilegeAudit) []OpsEntry {
	text := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if text == "" || text == "[]" {
		a.add(syoEmpty, "ops.json 为空，无任何运维账号", false)
		return nil
	}
	var entries []OpsEntry
	if err := json.Unmarshal([]byte(text), &entries); err != nil {
		a.add(syoBadJSON, err.Error(), true)
		return nil
	}
	return entries
}

func AuditServerOpsPrivilege(serverDir string) *OpsPrivilegeAudit {
	a := &OpsPrivilegeAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(syoMissing, "未配置服务器目录", true)
		return a
	}
	path := filepath.Join(serverDir, "ops.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(syoMissing, "缺少 ops.json", false)
		return a
	}
	bad, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(syoUnreadable, err.Error(), true)
		return a
	}
	if bad {
		a.add(syoSymlink, "ops.json 是符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, syoMaxFile)
	if err != nil {
		a.add(syoUnreadable, err.Error(), true)
		return a
	}
	entries := syoParse(data, a)
	a.Entries = len(entries)
	if len(entries) > syoMaxOps {
		a.add(syoTooMany, fmt.Sprintf("运维账号 %d 个，超过 %d 上限", len(entries), syoMaxOps), true)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		uuid := strings.ToLower(strings.TrimSpace(entry.UUID))
		if kind := syoUUIDShape(uuid); kind != "" {
			a.add(kind, uuid, true)
		}
		if _, dup := seen[uuid]; dup && uuid != "" {
			a.add(syoDuplicate, uuid, true)
		}
		seen[uuid] = struct{}{}
		if entry.Level < 0 || entry.Level > syoMaxLevel {
			a.add(syoOverLevel, fmt.Sprintf("level=%d 超出 0..%d", entry.Level, syoMaxLevel), true)
		}
		if entry.Level == 0 {
			a.add(syoBadLevel, "level=0 的运维账号无法执行管理命令", false)
		}
		if strings.TrimSpace(entry.Name) == "" {
			a.add(syoByName, "运维账号缺少 name 字段", false)
		}
		if entry.Bypass {
			a.add(syoBypass, fmt.Sprintf("%s 可绕过满员限制", uuid), false)
		}
	}
	return a
}
