package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	jmxReasonOK               = "ok"
	jmxReasonMissing          = "missing"
	jmxReasonUnreadable       = "unreadable"
	jmxReasonTooLarge         = "too-large"
	jmxReasonSymlink          = "symlink"
	jmxReasonUnauthenticated  = "jmx-unauthenticated"
	jmxReasonNoSSL            = "jmx-no-ssl"
	jmxReasonBroadBind        = "jmx-broad-bind"
	jmxReasonInlineSecret     = "jmx-inline-secret"
	jmxReasonPasswordReadable = "jmx-password-world-readable"
	jmxReasonPasswordUnsafe   = "jmx-password-unsafe"
	jmxMaxFileBytes           = 1 << 20
	jmxMaxFindings            = 128
	jmxMaxScripts             = 32
)

var jmxScriptCandidates = []string{
	"start.sh", "start.bat", "start.cmd",
	"run.sh", "run.bat", "run.cmd",
	"launch.sh", "launch.bat", "launch.cmd",
	"server.sh", "server.bat", "server.cmd",
	"jvm.args", "user_jvm_args.txt",
}

var jmxConfigCandidates = []string{
	"management.properties",
	filepath.Join("conf", "management.properties"),
	filepath.Join("config", "management.properties"),
	filepath.Join("conf", "jmxremote.password"),
	filepath.Join("config", "jmxremote.password"),
	filepath.Join("conf", "jmxremote.access"),
}

type JMXFinding = auditFinding

type JMXAudit struct {
	Dir      string
	Sources  []string
	Findings []JMXFinding
}

func (a JMXAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JMXFinding) bool { return f.Blocking })
}

func (a JMXAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f JMXFinding) bool { return !f.Blocking && f.Reason != jmxReasonOK })
}

func (a JMXAudit) Codes() []string {
	return findingCodesSkip(a.Findings, jmxReasonOK, func(f JMXFinding) string { return f.Reason })
}

func (a JMXAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现 JMX 远程管理配置"
	}
	parts := []string{}
	for _, f := range a.Findings {
		where := f.File
		if where == "" {
			where = "server"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", where, f.Reason))
		if len(parts) >= 6 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}
