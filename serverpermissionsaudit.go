package main

const (
	smnMaxFindings   = 32
	smnMaxFile       = 256 * 1024
	smnMaxEntries    = 400
	smnMaxInherit    = 3
	smnReasonMiss    = "missing"
	smnReasonLink    = "symlink"
	smnReasonLarge   = "too-large"
	smnReasonRead    = "unreadable"
	smnReasonEmpty   = "empty-config"
	smnReasonDefault = "default-oversized"
	smnReasonWild    = "wildcard-permission"
	smnReasonInherit = "inherit-depth"
	smnReasonNode    = "invalid-node"
	smnReasonCTRL    = "control-characters"
	smnReasonOpGrant = "op-grant"
	smnReasonBusy    = "too-many-entries"
	smnReasonUserOp  = "user-op-default"
)

type PermissionsFinding = auditFinding
type PermissionsAudit struct {
	ServerDir string
	Findings  []PermissionsFinding
}

func (a *PermissionsAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, smnMaxFindings, PermissionsFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *PermissionsAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PermissionsFinding) bool { return f.Blocking })
}
func (a *PermissionsAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
func (a *PermissionsAudit) Describe() string {
	return describeReasonDetail("permissions.yml 未发现风险", a.Findings, 12)
}

type smnEntry struct {
	Path  string
	Value string
}
