package main

import (
	"fmt"
	"strings"
)

const (
	mjmMaxFindings         = 48
	mjmMaxJarBytes         = 256 * 1024 * 1024
	mjmMaxManifest         = 64 * 1024
	mjmMaxEntries          = 20000
	mjmMaxMods             = 256
	mjmReasonOK            = "ok"
	mjmReasonMissing       = "missing"
	mjmReasonSymlink       = "symlink"
	mjmReasonTooLarge      = "too-large"
	mjmReasonBadJar        = "bad-jar"
	mjmReasonEntryOverflow = "entry-overflow"
	mjmReasonAgent         = "agent-class"
	mjmReasonClassPath     = "class-path-escape"
	mjmReasonMainClass     = "bad-main-class"
	mjmReasonManifestLarge = "manifest-too-large"
	mjmReasonBadName       = "bad-jar-name"
)

type ModJarFinding = auditFinding

type ModJarManifestAudit struct {
	ServerDir string
	Jars      int
	Findings  []ModJarFinding
}

func (a *ModJarManifestAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, mjmMaxFindings, ModJarFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *ModJarManifestAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ModJarFinding) bool { return f.Blocking })
}

func (a *ModJarManifestAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f ModJarFinding) bool { return f.Reason != mjmReasonOK && !f.Blocking })
}

func (a *ModJarManifestAudit) Describe() string {
	return describeFindings(a.Findings, func(f ModJarFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func mjmParseManifest(text string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var current string
	var builder strings.Builder
	flush := func() {
		if current == "" {
			return
		}
		value := strings.TrimSpace(builder.String())
		if _, exists := out[current]; !exists {
			out[current] = value
		}
		current = ""
		builder.Reset()
	}
	for _, line := range lines {
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, " ") && current != "" {
			builder.WriteString(strings.TrimPrefix(line, " "))
			continue
		}
		flush()
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		current = strings.ToLower(strings.TrimSpace(line[:idx]))
		builder.WriteString(strings.TrimSpace(line[idx+1:]))
	}
	flush()
	return out
}
