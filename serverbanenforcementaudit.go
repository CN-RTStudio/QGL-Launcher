package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	sbeMaxFindings = 22
	sbeMaxFile     = 512 * 1024
	sbeBadJSON     = "ban-json-invalid"
	sbeNoUUID      = "ban-entry-without-uuid"
	sbeNoReason    = "ban-entry-without-reason"
	sbeOpBanned    = "operator-also-banned"
	sbeWildcard    = "ip-ban-wildcard"
	sbeDupEntry    = "ban-duplicate"
	sbeLink        = "ban-file-symlink"
)

type BanEnforcementFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type BanEnforcementAudit struct {
	ServerDir string
	Findings  []BanEnforcementFinding
}

func (a *BanEnforcementAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= sbeMaxFindings {
		return
	}
	a.Findings = append(a.Findings, BanEnforcementFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *BanEnforcementAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *BanEnforcementAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *BanEnforcementAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "封禁与管理员名单未发现冲突"
	}
	sorted := make([]BanEnforcementFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].File != sorted[j].File {
			return sorted[i].File < sorted[j].File
		}
		return sorted[i].Detail < sorted[j].Detail
	})
	var b strings.Builder
	for i, f := range sorted {
		if i >= 12 {
			b.WriteString(fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		if i > 0 {
			b.WriteString("；")
		}
		b.WriteString(f.File)
		b.WriteString(":")
		b.WriteString(f.Reason)
		if f.Detail != "" {
			b.WriteString("(")
			b.WriteString(f.Detail)
			b.WriteString(")")
		}
	}
	return b.String()
}

type sbeBan struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	Created string `json:"created"`
}

func sbeLoad(serverDir, name string, a *BanEnforcementAudit) ([]sbeBan, bool) {
	path := filepath.Join(serverDir, name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(name, sbeBadJSON, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(name, sbeLink, "名单文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, sbeMaxFile)
	if err != nil {
		a.add(name, sbeBadJSON, err.Error(), true)
		return nil, false
	}
	var list []sbeBan
	if err := json.Unmarshal(data, &list); err != nil {
		a.add(name, sbeBadJSON, err.Error(), true)
		return nil, false
	}
	return list, true
}

func sbeOpNames(serverDir string) map[string]bool {
	data, err := readBoundedFile(filepath.Join(serverDir, "ops.json"), sbeMaxFile)
	if err != nil {
		return map[string]bool{}
	}
	var ops []sbeBan
	if err := json.Unmarshal(data, &ops); err != nil {
		return map[string]bool{}
	}
	out := make(map[string]bool, len(ops))
	for _, op := range ops {
		if key := strings.ToLower(strings.TrimSpace(op.UUID)); key != "" {
			out[key] = true
		}
	}
	return out
}

func sbeCheckBans(serverDir, file string, list []sbeBan, ops map[string]bool, a *BanEnforcementAudit, ipMode bool) {
	seen := make(map[string]int, len(list))
	for _, ban := range list {
		key := strings.ToLower(strings.TrimSpace(ban.UUID))
		if ipMode {
			key = strings.ToLower(strings.TrimSpace(ban.IP))
			if key == "*" || strings.HasSuffix(key, ".*") {
				a.add(file, sbeWildcard, "网段通配封禁: "+ban.IP, false)
			}
		} else if key == "" {
			a.add(file, sbeNoUUID, "封禁条目缺少 UUID: "+ban.Name, false)
		}
		if strings.TrimSpace(ban.Reason) == "" || cfgIsPlaceholder(ban.Reason) {
			a.add(file, sbeNoReason, "封禁无原因: "+ban.Name+ban.IP, false)
		}
		if key != "" {
			seen[key]++
			if seen[key] == 2 {
				a.add(file, sbeDupEntry, "重复封禁: "+key, false)
			}
		}
		if !ipMode && ops[key] {
			a.add(file, sbeOpBanned, "管理员同时被封禁: "+ban.Name, true)
		}
	}
}

func AuditServerBanEnforcement(serverDir string) *BanEnforcementAudit {
	a := &BanEnforcementAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("banned-players.json", sbeBadJSON, "未配置服务器目录", false)
		return a
	}
	ops := sbeOpNames(serverDir)
	if list, ok := sbeLoad(serverDir, "banned-players.json", a); ok {
		sbeCheckBans(serverDir, "banned-players.json", list, ops, a, false)
	}
	if list, ok := sbeLoad(serverDir, "banned-ips.json", a); ok {
		sbeCheckBans(serverDir, "banned-ips.json", list, ops, a, true)
	}
	return a
}
