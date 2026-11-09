package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func skLineHasURLCreds(line string) bool {
	idx := strings.Index(line, "://")
	if idx < 0 {
		return false
	}
	rest := line[idx+3:]
	at := strings.Index(rest, "@")
	if at <= 0 {
		return false
	}
	if strings.Index(rest[at:], "://") == 0 {
		return false
	}
	return strings.Contains(rest[:at], ":")
}

func AuditServerStartupSecrets(serverDir string) StartupSecretAudit {
	audit := StartupSecretAudit{Dir: serverDir}
	root, err := filepath.Abs(serverDir)
	if err != nil {
		audit.add("server-dir", skReasonUnreadable, "无法解析服务器目录", true)
		return audit
	}
	audit.Dir = root
	info, statErr := os.Lstat(root)
	if statErr != nil || !info.IsDir() {
		audit.add("server-dir", skReasonMissing, "服务器目录不存在", true)
		return audit
	}
	files := []string{}
	for _, name := range skScriptFiles {
		path := filepath.Join(root, name)
		if _, err := os.Lstat(path); err == nil {
			files = append(files, path)
		}
	}
	sort.Strings(files)
	if len(files) > skMaxFiles {
		files = files[:skMaxFiles]
	}
	for _, path := range files {
		skInspectFile(&audit, root, path)
	}
	if len(audit.Findings) == 0 {
		audit.add("startup", skReasonOK, "启动脚本均在凭据白名单外", false)
	}
	return audit
}
