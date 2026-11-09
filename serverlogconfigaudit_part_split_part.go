package main

import (
	"os"
	"path/filepath"
	"strings"
)

func lgInspectLogDir(a *LogConfigAudit, dir string) {
	info, err := os.Lstat(dir)
	if err != nil {
		return
	}
	rel, relErr := filepath.Rel(a.Dir, dir)
	if relErr != nil {
		rel = "logs"
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(rel, lgReasonLogSymlink, "日志目录是符号链接", true)
		return
	}
	if !info.IsDir() {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add(rel, lgReasonUnreadable, "日志目录不可读", false)
		return
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		count++
		if count > lgMaxLogFiles {
			a.add(rel, lgReasonLogVolume, "日志目录文件数量超过预算", false)
			break
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		relFile := filepath.Join(rel, entry.Name())
		if info.Mode()&os.ModeSymlink != 0 {
			a.add(relFile, lgReasonSymlink, "日志文件是符号链接", true)
			continue
		}
		if info.Size() > lgMaxLogBytes {
			a.add(relFile, lgReasonTooLarge, "单个日志文件超过体积预算", false)
		}
		if info.Mode().Perm()&0o004 != 0 {
			a.add(relFile, lgReasonWorldReadable, "日志文件对其他用户可读", false)
		}
	}
	if count > 1 && !strings.Contains(strings.ToLower(strings.Join(lgFileNames(entries), ",")), ".gz") {
		a.add(rel, lgReasonLogRotate, "历史日志未压缩或未轮转", false)
	}
}

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
