package main

import (
	"os"
)

func AuditServerAccessControl(serverDir string) AccessControlAudit {
	audit := AccessControlAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("", acReasonMissing, "服务器目录不存在", true)
		return audit
	}
	acInspectProperties(&audit, serverDir)
	acInspectOps(&audit, serverDir)
	acInspectWhitelist(&audit, serverDir)
	acInspectBans(&audit, serverDir, "banned-players.json")
	acInspectBans(&audit, serverDir, "banned-ips.json")
	if len(audit.Sources) == 0 {
		audit.add("", acReasonMissing, "未发现访问控制配置", false)
	}
	if len(audit.Findings) == 0 {
		audit.add("", acReasonOK, "访问控制配置未发现风险", false)
	}
	return audit
}

func (a AccessControlAudit) Describe() string {
	return describeTaggedFindings("访问控制未发现风险", a.Findings, acReasonOK, "server", acMaxFindings,
		func(f AccessControlFinding) string { return f.Reason },
		func(f AccessControlFinding) string { return f.File },
		func(f AccessControlFinding) string { return f.Detail })
}

func (a *AccessControlAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, acMaxFindings, AccessControlFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

type opEntry struct {
	UUID              string `json:"uuid"`
	Name              string `json:"name"`
	Level             int    `json:"level"`
	BypassesPlayerCap bool   `json:"bypassesPlayerLimit"`
}

type whitelistEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type bannedEntry struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	Created string `json:"created"`
}
