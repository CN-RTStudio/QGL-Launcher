package main

const (
	jaReasonOK             = "ok"
	jaReasonMissing        = "missing"
	jaReasonUnreadable     = "unreadable"
	jaReasonSymlink        = "symlink"
	jaReasonAgentOutside   = "agent-outside-server"
	jaReasonAgentTraversal = "agent-traversal"
	jaReasonAgentMissing   = "agent-not-found"
	jaReasonBootClasspath  = "bootclasspath-override"
	jaReasonDebugAgent     = "debug-agent"
	jaReasonJMXOpen        = "jmx-unauthenticated"
	jaReasonSecurityMgr    = "security-manager-allow"
	jaReasonAgentLib       = "agentlib-injected"
	jaReasonTooLarge       = "too-large"

	jaMaxScriptBytes = 1 << 20
	jaMaxScripts     = 16
	jaMaxFindings    = 48
)

var jaScriptNames = []string{
	"start.sh",
	"start.bat",
	"start.cmd",
	"run.sh",
	"run.bat",
	"run.cmd",
	"launch.sh",
	"launch.bat",
	"user_jvm_args.txt",
	"args.txt",
	"jvm.args",
}

type JVMAgentFinding = auditFinding

type JVMAgentAudit struct {
	Dir      string
	Scripts  []string
	Findings []JVMAgentFinding
}

func (a JVMAgentAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JVMAgentFinding) bool { return f.Blocking })
}

func (a JVMAgentAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f JVMAgentFinding) bool { return !f.Blocking && f.Reason != jaReasonOK })
}
