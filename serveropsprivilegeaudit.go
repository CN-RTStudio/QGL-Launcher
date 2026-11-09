package main

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
