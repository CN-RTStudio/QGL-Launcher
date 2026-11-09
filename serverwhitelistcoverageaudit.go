package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	swcMaxFindings = 24
	swcMaxFile     = 512 * 1024
	swcMissProps   = "properties-missing"
	swcReadProps   = "properties-unreadable"
	swcOffButList  = "whitelist-off-with-entries"
	swcOnNoFile    = "whitelist-enabled-without-file"
	swcEnforceBad  = "enforce-whitelist-without-whitelist"
	swcBadJSON     = "whitelist-json-invalid"
	swcNoUUID      = "whitelist-entry-without-uuid"
	swcDupName     = "whitelist-duplicate-name"
	swcOpNotListed = "operator-not-whitelisted"
	swcLink        = "whitelist-symlink"
)

type WhitelistCoverageFinding = auditFinding

type WhitelistCoverageAudit struct {
	ServerDir string
	Findings  []WhitelistCoverageFinding
}

func (a *WhitelistCoverageAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, swcMaxFindings, WhitelistCoverageFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WhitelistCoverageAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WhitelistCoverageFinding) bool { return f.Blocking })
}

func (a *WhitelistCoverageAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WhitelistCoverageAudit) Describe() string {
	return describeReasonDetail("白名单覆盖检查通过", a.Findings, 12)
}

type swcEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

func swcBool(props map[string]string, key string) (bool, bool) {
	return propsBoolValue(props, key)
}

func swcLoadEntries(serverDir string, a *WhitelistCoverageAudit) ([]swcEntry, bool) {
	path := filepath.Join(serverDir, "whitelist.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add("whitelist.json", swcReadProps, err.Error(), true)
		return nil, false
	}
	if link {
		a.add("whitelist.json", swcLink, "白名单文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, swcMaxFile)
	if err != nil {
		a.add("whitelist.json", swcReadProps, err.Error(), true)
		return nil, false
	}
	var entries []swcEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		a.add("whitelist.json", swcBadJSON, err.Error(), true)
		return nil, false
	}
	return entries, true
}
