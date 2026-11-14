package main

import ()

func (a JarClassPathAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JarCPFinding) bool { return f.Blocking })
}

func (a JarClassPathAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f JarCPFinding) bool { return !f.Blocking && f.Reason != jarCpReasonOK })
}
