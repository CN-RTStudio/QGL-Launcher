package main

const (
	pmReasonOK            = "ok"
	pmReasonMissing       = "missing"
	pmReasonSymlink       = "symlink"
	pmReasonTooLarge      = "too-large"
	pmReasonWorldWritable = "world-writable"
	pmReasonUnreadable    = "unreadable"
	pmReasonWildcardGrant = "wildcard-grant"
	pmReasonDefaultOp     = "default-op"
	pmReasonDefaultAllow  = "default-allow"
	pmReasonOpCommand     = "op-command-grant"
	pmReasonUnknownNode   = "unknown-plugin-node"
	pmReasonTooManyFiles  = "file-overflow"

	pmMaxFileBytes = 512 << 10
	pmMaxFiles     = 24
	pmMaxFindings  = 48
)

var pmCandidateFiles = []string{
	"permissions.yml",
	"config/permissions.yml",
	"plugins/PluginPermissions/permissions.yml",
}
var pmDangerousNodes = []string{
	"bukkit.command.op",
	"minecraft.command.op",
	"bukkit.command.stop",
	"bukkit.command.reload",
	"essentials.give",
	"worldedit.*",
}

type PermissionConfigFinding = auditFinding
type PermissionConfigAudit struct {
	Dir      string
	Files    []string
	Findings []PermissionConfigFinding
}

func (a PermissionConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PermissionConfigFinding) bool { return f.Blocking })
}
func (a PermissionConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PermissionConfigFinding) bool { return !f.Blocking && f.Reason != pmReasonOK })
}
