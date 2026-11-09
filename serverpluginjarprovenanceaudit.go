package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	pjReasonOK            = "ok"
	pjReasonMissing       = "missing"
	pjReasonEmpty         = "empty-plugins-dir"
	pjReasonUnreadable    = "unreadable"
	pjReasonTooLarge      = "too-large"
	pjReasonTooMany       = "too-many"
	pjReasonSymlink       = "symlink"
	pjReasonBadName       = "bad-name"
	pjReasonNoDescriptor  = "missing-plugin-yml"
	pjReasonNoMain        = "missing-main-class"
	pjReasonBadMain       = "bad-main-class"
	pjReasonNestedJar     = "nested-jar"
	pjReasonExecBit       = "executable-bit"
	pjReasonShellClass    = "shell-capable-main"
	pjReasonUnsigned      = "unsigned"
	pjReasonWeakDigest    = "weak-digest"
	pjReasonDuplicateJar  = "duplicate-jar"
	pjReasonTooManyFiles  = "too-many-entries"

	pjMaxJarBytes    = 64 << 20
	pjMaxJars        = 128
	pjMaxEntries     = 4096
	pjMaxFindings    = 160
	pjMaxMainLen     = 200
	pjMaxNestedDepth = 2
)

var pjSelectedPaths = []string{
	"META-INF/MANIFEST.MF",
	"META-INF/",
	"plugin.yml",
	"paper-plugin.yml",
	"bungee.yml",
	"velocity-plugin.json",
}

var pjShellyMainTokens = []string{
	"runtime.exec",
	"processbuilder",
	"scriptengine",
	"shell",
	"cmd",
	"exec",
}

type PluginJarFinding struct {
	Jar      string
	Reason   string
	Detail   string
	Blocking bool
}

type PluginJarAudit struct {
	Dir      string
	Jars     []string
	Findings []PluginJarFinding
}

func (a PluginJarAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginJarFinding) bool { return f.Blocking })
}

func (a PluginJarAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != pjReasonOK {
			return true
		}
	}
	return false
}

func (a PluginJarAudit) Describe() string {
	var parts []string
	for _, f := range a.Findings {
		if f.Reason == pjReasonOK {
			continue
		}
		label := f.Jar
		if label == "" {
			label = "plugins"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= pjMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "插件包结构未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *PluginJarAudit) add(jar, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pjMaxFindings, PluginJarFinding{Jar: jar, Reason: reason, Detail: detail, Blocking: blocking})
}
