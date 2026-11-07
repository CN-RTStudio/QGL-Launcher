package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	opxMaxFindings = 16
	opxMaxFile     = 256 * 1024
	opxMaxOps      = 8
	opxMiss        = "ops-file-missing"
	opxRead        = "ops-file-unreadable"
	opxLink        = "ops-file-symlink"
	opxEmpty       = "ops-file-empty"
	opxJSON        = "ops-json-invalid"
	opxShape       = "ops-entry-invalid"
	opxUUID        = "ops-uuid-invalid"
	opxUUIDDup     = "ops-uuid-duplicate"
	opxNameEmpty   = "ops-name-empty"
	opxLevelRange  = "ops-level-invalid"
	opxLevelTop    = "ops-level-maximum"
	opxBypass      = "ops-bypass-limit"
	opxTooMany     = "ops-count-excessive"
)

var opxUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type OpSecurityFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type OpSecurityAudit struct {
	ServerDir string
	Findings  []OpSecurityFinding
}

type opxEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               int    `json:"level"`
	BypassesPlayerLimit bool   `json:"bypassesPlayerLimit"`
}

func (a *OpSecurityAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= opxMaxFindings {
		return
	}
	a.Findings = append(a.Findings, OpSecurityFinding{File: "ops.json", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *OpSecurityAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *OpSecurityAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *OpSecurityAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "OP 名单权限配置处于安全区间"
	}
	sorted := make([]OpSecurityFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Detail < sorted[j].Detail
	})
	var b strings.Builder
	for i, f := range sorted {
		if i >= 10 {
			b.WriteString(fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		if i > 0 {
			b.WriteString("；")
		}
		b.WriteString(f.Reason)
		if f.Detail != "" {
			b.WriteString("(")
			b.WriteString(f.Detail)
			b.WriteString(")")
		}
	}
	return b.String()
}

func opxLoadOps(serverDir string, a *OpSecurityAudit) ([]opxEntry, bool) {
	path := filepath.Join(serverDir, "ops.json")
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		a.add(opxMiss, "缺少 ops.json", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(opxRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(opxLink, "OP 名单是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, opxMaxFile)
	if err != nil {
		a.add(opxRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(strings.TrimSpace(string(data)), "\ufeff")
	if text == "" {
		a.add(opxEmpty, "ops.json 为空", false)
		return nil, false
	}
	var entries []opxEntry
	if err := json.Unmarshal([]byte(text), &entries); err != nil {
		a.add(opxJSON, err.Error(), true)
		return nil, false
	}
	return entries, true
}

func opxAuditEntry(entry opxEntry, index int, seen map[string]int, a *OpSecurityAudit) {
	label := fmt.Sprintf("#%d", index)
	uuid := strings.TrimSpace(entry.UUID)
	name := strings.TrimSpace(entry.Name)
	if uuid == "" || !opxUUIDPattern.MatchString(uuid) {
		a.add(opxUUID, label+" uuid 格式非法", true)
	} else {
		key := strings.ToLower(uuid)
		if first, ok := seen[key]; ok {
			a.add(opxUUIDDup, fmt.Sprintf("%s 与 #%d 使用同一 uuid", label, first), true)
		} else {
			seen[key] = index
		}
	}
	if name == "" {
		a.add(opxNameEmpty, label+" 缺少玩家名", true)
	}
	if entry.Level < 1 || entry.Level > 4 {
		a.add(opxLevelRange, fmt.Sprintf("%s level=%d 不在 1..4", label, entry.Level), true)
	} else if entry.Level == 4 {
		a.add(opxLevelTop, label+" 具备 4 级完全控制权限", false)
	}
	if entry.BypassesPlayerLimit {
		a.add(opxBypass, label+" 可无视玩家上限进入服务器", false)
	}
}

func AuditServerOpSecurity(serverDir string) *OpSecurityAudit {
	a := &OpSecurityAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(opxMiss, "未配置服务器目录", false)
		return a
	}
	entries, ok := opxLoadOps(serverDir, a)
	if !ok {
		return a
	}
	if len(entries) > opxMaxOps {
		a.add(opxTooMany, fmt.Sprintf("OP 条目 %d 超过建议上限 %d", len(entries), opxMaxOps), false)
	}
	seen := map[string]int{}
	for i, entry := range entries {
		if entry.UUID == "" && entry.Name == "" && entry.Level == 0 {
			a.add(opxShape, fmt.Sprintf("#%d 是空条目", i), true)
			continue
		}
		opxAuditEntry(entry, i, seen, a)
	}
	return a
}
