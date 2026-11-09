package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func ppValidIPv4(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		value := 0
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
			value = value*10 + int(ch-'0')
		}
		if value > 255 {
			return false
		}
	}
	return true
}

func ppAuditOperators(a *PlayerPrivacyAudit, dir string) {
	data := ppLoadJSON(a, dir, "ops.json")
	if len(data) == 0 {
		return
	}
	var entries []ppOpEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		a.add("ops.json", ppReasonMalformedJSON, "管理员列表不是合法 JSON 数组", true)
		return
	}
	full := 0
	bypass := 0
	bad := 0
	for _, e := range entries {
		if !ppUUIDPattern.MatchString(strings.ToLower(strings.TrimSpace(e.UUID))) {
			bad++
		}
		if e.Level >= 4 {
			full++
		}
		if e.BypassesPlayerLimit {
			bypass++
		}
	}
	if bad > 0 {
		a.add("ops.json", ppReasonBadName, fmt.Sprintf("%d 条管理员条目 UUID 非法", bad), true)
	}
	if full > 0 {
		a.add("ops.json", ppReasonOpLevel, fmt.Sprintf("%d 个管理员拥有 4 级权限", full), false)
	}
	if bypass > 0 {
		a.add("ops.json", ppReasonBypassLimit, fmt.Sprintf("%d 个管理员绕过人数上限", bypass), false)
	}
}

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
