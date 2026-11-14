package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

func (a LibraryAudit) Describe() string {
	return describeLabeledFindings("未发现依赖库", a.Findings, 4, "",
		func(f LibraryFinding) string { return f.File },
		func(f LibraryFinding) string { return f.Reason })
}
func (a LibraryAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f LibraryFinding) bool { return f.Blocking }, func(f LibraryFinding) bool { return !f.Blocking && f.Reason != libReasonOK })
	return fmt.Sprintf("jars=%d findings=%d blocking=%d warnings=%d", len(a.Jars), len(a.Findings), blocking, warnings)
}

func (a *LibraryAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, libMaxFindings, LibraryFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func libArtifactKey(name string) string {
	lower := strings.ToLower(strings.TrimSuffix(filepath.Base(name), filepath.Ext(name)))
	for _, marker := range []string{"-sources", "-javadoc", "-natives"} {
		lower = strings.TrimSuffix(lower, marker)
	}
	segments := strings.Split(lower, "-")
	kept := []string{}
	for _, segment := range segments {
		if segment == "" || libLooksVersion(segment) {
			continue
		}
		kept = append(kept, segment)
	}
	if len(kept) == 0 {
		return lower
	}
	return strings.Join(kept, "-")
}
