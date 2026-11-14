package main

import (
	"fmt"
	"strings"
)

func (a JarClassPathAudit) Codes() []string {
	return findingCodesSkip(a.Findings, jarCpReasonOK, func(f JarCPFinding) string { return f.Reason })
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
	blocking, warnings := auditTally(a.Findings, func(f JarCPFinding) bool { return f.Blocking }, func(f JarCPFinding) bool { return !f.Blocking && f.Reason != jarCpReasonOK })
	return fmt.Sprintf("jars=%d findings=%d blocking=%d warnings=%d", a.Jars, len(a.Findings), blocking, warnings)
}
