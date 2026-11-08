package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	skReasonOK            = "ok"
	skReasonSymlink       = "symlink"
	skReasonTooLarge      = "too-large"
	skReasonWorldWritable = "world-writable"
	skReasonWorldReadable = "world-readable"
	skReasonUnreadable    = "unreadable"
	skReasonPlainSecret   = "plaintext-secret"
	skReasonPropSecret    = "system-property-secret"
	skReasonURLCreds      = "url-credentials"
	skReasonTokenArg      = "token-argument"
	skReasonRCONArg       = "rcon-password-argument"
	skReasonEnvSecret     = "env-secret"
	skReasonMissing       = "missing"

	skMaxFileBytes = 256 << 10
	skMaxFiles     = 16
	skMaxFindings  = 48
)

var skScriptFiles = []string{
	"start.sh",
	"start.bat",
	"start.cmd",
	"run.sh",
	"run.bat",
	"run.cmd",
	"launch.sh",
	"launch.bat",
	"launch.cmd",
	"user_jvm_args.txt",
	"jvm.args",
	"server.args",
}

var skSecretKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"apikey",
	"api-key",
	"api_key",
	"accesskey",
	"access-key",
	"rcon.password",
	"rcon-password",
}

type StartupSecretFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type StartupSecretAudit struct {
	Dir      string
	Files    []string
	Findings []StartupSecretFinding
}

func (a StartupSecretAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f StartupSecretFinding) bool { return f.Blocking })
}

func (a StartupSecretAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != skReasonOK {
			return true
		}
	}
	return false
}

func (a StartupSecretAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == skReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "startup"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= skMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "启动脚本未发现明文凭据"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *StartupSecretAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= skMaxFindings {
		return
	}
	a.Findings = append(a.Findings, StartupSecretFinding{
		File:     file,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}
