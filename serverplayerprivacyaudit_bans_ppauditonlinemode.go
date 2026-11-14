package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func ppAuditOnlineMode(a *PlayerPrivacyAudit, dir string) {
	path := filepath.Join(dir, "server.properties")
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return
	}
	data, readErr := readBoundedFile(path, 1<<20)
	if readErr != nil {
		return
	}
	props := pxParseProperties(string(data))
	if value, ok := props["online-mode"]; ok {
		if strings.EqualFold(strings.TrimSpace(value), "false") {
			a.add("server.properties", ppReasonOnlineMode, "在线模式关闭，玩家身份可被冒充", false)
		}
	}
}
func ppAuditLogIP(a *PlayerPrivacyAudit, dir string) {
	path := filepath.Join(dir, "logs", "latest.log")
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Size() > ppMaxLogBytes {
		return
	}
	data, readErr := readBoundedFile(path, ppMaxLogBytes)
	if readErr != nil {
		return
	}
	hits := len(ppLogIP.FindAllString(string(data), -1))
	if hits > ppMaxLogIPCount {
		a.add("logs/latest.log", ppReasonLogIPLeak, fmt.Sprintf("日志残留 %d 处明文地址", hits), false)
	}
}

func AuditServerPlayerPrivacy(serverDir string) PlayerPrivacyAudit {
	audit := PlayerPrivacyAudit{Dir: serverDir}
	root, err := filepath.Abs(serverDir)
	if err != nil {
		audit.add("server-dir", ppReasonUnreadable, "无法解析服务器目录", true)
		return audit
	}
	audit.Dir = root
	info, statErr := os.Lstat(root)
	if statErr != nil || !info.IsDir() {
		audit.add("server-dir", ppReasonMissing, "服务器目录不存在", true)
		return audit
	}
	now := time.Now()
	ppAuditUserCache(&audit, root, now)
	ppAuditBannedIPs(&audit, root)
	ppAuditOperators(&audit, root)
	ppAuditOnlineMode(&audit, root)
	ppAuditLogIP(&audit, root)
	if len(audit.Findings) == 0 {
		audit.add("player-data", ppReasonOK, "玩家身份数据均在预算内", false)
	}
	return audit
}

type ppOpEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               int    `json:"level"`
	BypassesPlayerLimit bool   `json:"bypassesPlayerLimit"`
}
type PlayerPrivacyFinding struct {
	Source   string
	Reason   string
	Detail   string
	Blocking bool
}
type PlayerPrivacyAudit struct {
	Dir      string
	Files    []string
	Findings []PlayerPrivacyFinding
}
