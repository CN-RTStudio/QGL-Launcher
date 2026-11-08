package main

import (
	"fmt"
	"path/filepath"
	"sort"
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

type JarClassPathAudit struct {
	Dir      string
	Jars     int
	Findings []JarCPFinding
}

func (a JarClassPathAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JarCPFinding) bool { return f.Blocking })
}

func (a JarClassPathAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != jarCpReasonOK {
			return true
		}
	}
	return false
}

func (a JarClassPathAudit) Codes() []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, f := range a.Findings {
		if f.Reason == jarCpReasonOK || seen[f.Reason] {
			continue
		}
		seen[f.Reason] = true
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}

func (a JarClassPathAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("已扫描 %d 个 jar，未发现 Class-Path 注入", a.Jars)
	}
	parts := []string{}
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s[%s](%s)", f.Jar, f.Entry, f.Reason))
		if len(parts) >= 5 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a JarClassPathAudit) Summary() string {
	blocking := 0
	warnings := 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != jarCpReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("jars=%d findings=%d blocking=%d warnings=%d", a.Jars, len(a.Findings), blocking, warnings)
}
