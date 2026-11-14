package main

import ()

func AuditPluginJarEntries(serverDir string) *PluginJarEntryAudit {
	a := &PluginJarEntryAudit{ServerDir: serverDir}
	runJarRootAudit(serverDir, mpeReasonMissing, mpeReasonSymlink, "未发现 plugins 目录或 JAR",
		func(file, reason, detail string, blocking bool) { a.add(file, reason, detail, blocking) },
		func(dir string) { mpeScanDir(a, dir) },
		func() int { return a.Jars },
		func() int { return len(a.Findings) })
	return a
}

func (a *PluginJarEntryAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginJarEntryFinding) bool { return f.Blocking })
}

func (a *PluginJarEntryAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginJarEntryFinding) bool { return f.Reason != mpeReasonOK && !f.Blocking })
}
