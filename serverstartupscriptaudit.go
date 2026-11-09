package main

import (
	"fmt"
	"strings"
)

const (
	startupReasonOK             = "ok"
	startupReasonMissing        = "missing"
	startupReasonSymlink        = "symlink"
	startupReasonNotRegular     = "not-regular"
	startupReasonTooLarge       = "too-large"
	startupReasonUnreadable     = "unreadable"
	startupReasonRemotePipe     = "remote-pipe"
	startupReasonEncodedPower   = "encoded-powershell"
	startupReasonReverseShell   = "reverse-shell"
	startupReasonBase64Pipe     = "base64-pipe"
	startupReasonJavaAgent      = "javaagent"
	startupReasonDownloadCradle = "download-cradle"
	startupReasonEvalShell      = "eval-shell"
	startupReasonBroadDelete    = "broad-delete"
	startupReasonWorldChmod     = "world-writable-chmod"
	startupReasonSudo           = "sudo-escalation"
	startupReasonEmbeddedSecret = "embedded-secret"
	startupMaxBytes             = 1 << 20
	startupMaxLineBytes         = 4096
	startupMaxFindings          = 256
	startupTruncatedDetailRunes = 160
)

var startupScriptNames = []string{
	"start.sh",
	"start.bat",
	"start.cmd",
	"run.sh",
	"run.bat",
	"run.cmd",
	"launch.sh",
	"launch.bat",
	"server.sh",
	"server.bat",
}

type StartupFinding struct {
	Script   string
	Line     int
	Reason   string
	Detail   string
	Blocking bool
}

type ServerStartupAudit struct {
	Dir      string
	Scripts  []string
	Findings []StartupFinding
}

func (a *ServerStartupAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f StartupFinding) bool { return f.Blocking })
}

func (a *ServerStartupAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f StartupFinding) bool {
		return !f.Blocking && f.Reason != startupReasonOK && f.Reason != startupReasonMissing
	})
}

func (a *ServerStartupAudit) Codes() []string {
	return findingCodes(a.Findings, func(f StartupFinding) string { return f.Reason })
}

func (a *ServerStartupAudit) Describe() string {
	if a == nil || len(a.Findings) == 0 {
		return "启动脚本审计: 未发现脚本"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == startupReasonOK || f.Reason == startupReasonMissing {
			continue
		}
		if f.Line > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d %s(%s)", f.Script, f.Line, f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %s(%s)", f.Script, f.Reason, f.Detail))
	}
	if len(parts) == 0 {
		return "启动脚本审计: 通过"
	}
	return strings.Join(parts, "; ")
}

func (a *ServerStartupAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f StartupFinding) bool { return f.Blocking }, func(f StartupFinding) bool {
		return !f.Blocking && f.Reason != startupReasonOK && f.Reason != startupReasonMissing
	})
	return fmt.Sprintf("启动脚本 %d 个，阻断 %d，告警 %d", len(a.Scripts), blocking, warnings)
}

func hasAnyToken(lower string, tokens ...string) bool {
	for _, t := range tokens {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}
