package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
