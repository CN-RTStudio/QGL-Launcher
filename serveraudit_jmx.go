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

func (a JMXAudit) Summary() string {
	blocking := 0
	warnings := 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != jmxReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("sources=%d findings=%d blocking=%d warnings=%d", len(a.Sources), len(a.Findings), blocking, warnings)
}

func (a *JMXAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, jmxMaxFindings, JMXFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func jmxIsLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), `"'`)
	if host == "" {
		return false
	}
	lower := strings.ToLower(host)
	switch lower {
	case "localhost", "127.0.0.1", "::1", "[::1]", "0:0:0:0:0:0:0:1":
		return true
	}
	return false
}

func jmxOptionValue(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(key):]
	rest = strings.TrimLeft(rest, "= ")
	for i := 0; i < len(rest); i++ {
		if rest[i] == ' ' || rest[i] == '\t' || rest[i] == '"' || rest[i] == '\'' || rest[i] == ';' {
			return rest[:i]
		}
	}
	return rest
}
