package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *ServerStraySecretAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f StraySecretFinding) bool { return f.Blocking }, func(f StraySecretFinding) bool { return !f.Blocking && f.Reason != strayReasonOK })
	return fmt.Sprintf("凭据扫描 %d 个候选，阻断 %d，告警 %d", len(a.Scanned), blocking, warnings)
}

func strayNameMatches(name string) bool {
	lower := strings.ToLower(name)
	if straySecretNames[lower] {
		return true
	}
	for _, suffix := range []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return strings.HasPrefix(lower, "id_") && !strings.HasSuffix(lower, ".pub")
}

func AuditServerStraySecrets(serverDir string) *ServerStraySecretAudit {
	audit := &ServerStraySecretAudit{Dir: serverDir}
	if strings.TrimSpace(serverDir) == "" {
		return audit
	}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		return audit
	}
	for _, rel := range straySecretDirs {
		dir := filepath.Join(serverDir, rel)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strayNameMatches(entry.Name()) {
				continue
			}
			if len(audit.Scanned) >= strayMaxCandidates {
				return audit
			}
			display := entry.Name()
			if rel != "." {
				display = filepath.Join(rel, entry.Name())
			}
			auditStraySecretFile(audit, filepath.Join(dir, entry.Name()), display)
		}
	}
	if len(audit.Scanned) == 0 {
		audit.Findings = append(audit.Findings, StraySecretFinding{Reason: strayReasonOK, Detail: "服务器目录没有候选凭据文件"})
	}
	return audit
}
