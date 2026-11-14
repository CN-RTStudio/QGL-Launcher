package main

import (
	"os"
	"path/filepath"
)

func lgFileNames(entries []os.DirEntry) []string {
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func AuditServerLogConfig(serverDir string) LogConfigAudit {
	audit := LogConfigAudit{Dir: serverDir}
	found := 0
	for _, rel := range lgConfigCandidates {
		path := filepath.Join(serverDir, rel)
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		found++
		lgInspectConfig(&audit, path)
	}
	if found == 0 {
		audit.add("log-config", lgReasonMissing, "未使用外部日志配置文件", false)
	}
	lgInspectLogDir(&audit, filepath.Join(serverDir, "logs"))
	if len(audit.Findings) == 0 {
		audit.add("log-config", lgReasonOK, "日志配置与日志目录符合预期", false)
	}
	return audit
}
