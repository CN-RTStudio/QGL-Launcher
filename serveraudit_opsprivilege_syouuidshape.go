package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func syoUUIDShape(uuid string) string {
	clean := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(uuid)), "-", "")
	if len(clean) != 32 {
		return syoBadUUID
	}
	for _, r := range clean {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return syoBadUUID
		}
	}
	if clean[12] == '3' && strings.ContainsRune("89ab", rune(clean[16])) {
		return syoOfflineUUID
	}
	return ""
}
func syoParse(data []byte, a *OpsPrivilegeAudit) []OpsEntry {
	text := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if text == "" || text == "[]" {
		a.add(syoEmpty, "ops.json 为空，无任何运维账号", false)
		return nil
	}
	var entries []OpsEntry
	if err := json.Unmarshal([]byte(text), &entries); err != nil {
		a.add(syoBadJSON, err.Error(), true)
		return nil
	}
	return entries
}

func AuditServerOpsPrivilege(serverDir string) *OpsPrivilegeAudit {
	a := &OpsPrivilegeAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(syoMissing, "未配置服务器目录", true)
		return a
	}
	path := filepath.Join(serverDir, "ops.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(syoMissing, "缺少 ops.json", false)
		return a
	}
	bad, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(syoUnreadable, err.Error(), true)
		return a
	}
	if bad {
		a.add(syoSymlink, "ops.json 是符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, syoMaxFile)
	if err != nil {
		a.add(syoUnreadable, err.Error(), true)
		return a
	}
	entries := syoParse(data, a)
	a.Entries = len(entries)
	if len(entries) > syoMaxOps {
		a.add(syoTooMany, fmt.Sprintf("运维账号 %d 个，超过 %d 上限", len(entries), syoMaxOps), true)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		uuid := strings.ToLower(strings.TrimSpace(entry.UUID))
		if kind := syoUUIDShape(uuid); kind != "" {
			a.add(kind, uuid, true)
		}
		if _, dup := seen[uuid]; dup && uuid != "" {
			a.add(syoDuplicate, uuid, true)
		}
		seen[uuid] = struct{}{}
		if entry.Level < 0 || entry.Level > syoMaxLevel {
			a.add(syoOverLevel, fmt.Sprintf("level=%d 超出 0..%d", entry.Level, syoMaxLevel), true)
		}
		if entry.Level == 0 {
			a.add(syoBadLevel, "level=0 的运维账号无法执行管理命令", false)
		}
		if strings.TrimSpace(entry.Name) == "" {
			a.add(syoByName, "运维账号缺少 name 字段", false)
		}
		if entry.Bypass {
			a.add(syoBypass, fmt.Sprintf("%s 可绕过满员限制", uuid), false)
		}
	}
	return a
}
