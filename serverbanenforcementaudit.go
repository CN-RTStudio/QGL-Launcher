package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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

type BanEnforcementFinding = auditFinding
type BanEnforcementAudit struct {
	ServerDir string
	Findings  []BanEnforcementFinding
}

func (a *BanEnforcementAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sbeMaxFindings, BanEnforcementFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *BanEnforcementAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BanEnforcementFinding) bool { return f.Blocking })
}
func (a *BanEnforcementAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
func (a *BanEnforcementAudit) Describe() string {
	return describeFileDetail("封禁与管理员名单未发现冲突", a.Findings, 12)
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
