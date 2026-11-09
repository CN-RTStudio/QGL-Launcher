package main

var lgJNDITokens = []string{
	"${jndi:",
	"${jndi ",
	"jndilookup",
	"initialcontext",
}
var lgLookupTokens = []string{
	"${env:",
	"${sys:",
	"${ctx:",
	"${docker:",
	"${k8s:",
	"${date:",
	"${java:",
	"${lower:",
	"${upper:",
}

type LogConfigFinding = auditFinding
type LogConfigAudit struct {
	Dir      string
	Files    []string
	Findings []LogConfigFinding
}

func (a LogConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f LogConfigFinding) bool { return f.Blocking })
}
func (a LogConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f LogConfigFinding) bool { return !f.Blocking && f.Reason != lgReasonOK })
}
