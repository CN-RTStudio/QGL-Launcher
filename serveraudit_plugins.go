package main

import (
	"path/filepath"
	"strings"
)

const (
	jarCpReasonOK          = "ok"
	jarCpReasonMissing     = "missing"
	jarCpReasonUnreadable  = "unreadable"
	jarCpReasonTooLarge    = "too-large"
	jarCpReasonTooMany     = "too-many"
	jarCpReasonNotZip      = "not-zip"
	jarCpReasonNoManifest  = "manifest-missing"
	jarCpReasonAbsolute    = "classpath-absolute"
	jarCpReasonTraversal   = "classpath-traversal"
	jarCpReasonRemote      = "classpath-remote"
	jarCpReasonDuplicate   = "classpath-duplicate"
	jarCpReasonAgentEntry  = "agent-entry"
	jarCpMaxJars           = 120
	jarCpMaxManifestBytes  = 512 << 10
	jarCpMaxEntries        = 64
	jarCpMaxFindingsPerJar = 24
	jarCpClassPathAttr     = "class-path:"
	jarCpManifestPath      = "META-INF/MANIFEST.MF"
)

var jarCpScanRoots = []string{
	".",
	"plugins",
	filepath.Join("plugins", "update"),
}

type JarCPFinding struct {
	Jar      string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

func (a *JarClassPathAudit) add(jar, entry, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, jarCpMaxFindingsPerJar*jarCpMaxJars, JarCPFinding{Jar: jar, Entry: entry, Reason: reason, Detail: detail, Blocking: blocking})
}
func jarCPUnfoldManifest(data []byte) []string {
	raw := strings.ReplaceAll(string(data), "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := []string{}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, " ") && len(lines) > 0 {
			lines[len(lines)-1] += strings.TrimPrefix(line, " ")
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
func jarCPEntries(value string) []string {
	out := []string{}
	for _, part := range strings.Fields(value) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}
