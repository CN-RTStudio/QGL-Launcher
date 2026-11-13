package main

const (
	scyMaxFindings = 32
	scyMaxFile     = 256 * 1024
	scyMaxAliases  = 64
	scyReasonMiss  = "missing"
	scyReasonLink  = "symlink"
	scyReasonLarge = "too-large"
	scyReasonRead  = "unreadable"
	scyReasonEmpty = "empty-config"
	scyReasonName  = "invalid-alias-name"
	scyReasonMeth  = "alias-without-command"
	scyReasonChain = "command-chaining"
	scyReasonPriv  = "privileged-alias"
	scyReasonCtl   = "control-characters"
	scyReasonMany  = "too-many-aliases"
)

type CommandsYmlFinding = auditFinding
type CommandsYmlAudit struct {
	ServerDir string
	Findings  []CommandsYmlFinding
}
type commandsYmlBlock struct {
	Name     string
	Commands []string
}

func (a *CommandsYmlAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, scyMaxFindings, CommandsYmlFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *CommandsYmlAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CommandsYmlFinding) bool { return f.Blocking })
}
