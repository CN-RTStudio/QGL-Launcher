package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func swfValidUUID(value string) bool {
	clean := strings.ReplaceAll(value, "-", "")
	if len(clean) != 32 {
		return false
	}
	for _, c := range clean {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func swfValidName(value string) bool {
	return propsValidName(value)
}

func AuditServerWhitelistFile(serverDir string) *WhitelistFileAudit {
	a := &WhitelistFileAudit{ServerDir: serverDir}
	const rel = "whitelist.json"
	if serverDir == "" {
		a.add(".", swfReasonMiss, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", swfReasonLink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, swfReasonLink, "白名单文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, swfMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, swfReasonLarge, fmt.Sprintf("白名单文件超过 %d 字节", swfMaxFile), true)
			return a
		}
		a.add(rel, swfReasonRead, "白名单文件不可读", false)
		return a
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		a.add(rel, swfReasonShape, "白名单文件为空", true)
		return a
	}
	var entries []whitelistFileEntry
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
		a.add(rel, swfReasonShape, "白名单文件不是合法的 JSON 数组", true)
		return a
	}
	if len(entries) > swfMaxEntries {
		a.add(rel, swfReasonMany, fmt.Sprintf("条目数量 %d 超过 %d", len(entries), swfMaxEntries), true)
	}
	if len(entries) == 0 {
		a.add(rel, swfReasonEmpty, "白名单开启但条目为空，所有玩家都会被拒绝", false)
		return a
	}

	seen := make(map[string]bool, len(entries))
	for i, entry := range entries {
		label := fmt.Sprintf("#%d", i+1)
		if !swfValidUUID(entry.UUID) {
			a.add(rel, swfReasonUUID, label+" uuid 格式非法", true)
		}
		if strings.ContainsAny(entry.Name, "\x00\r\n\t") {
			a.add(rel, swfReasonCtl, label+" 玩家名含控制字符", true)
			continue
		}
		if !swfValidName(entry.Name) {
			a.add(rel, swfReasonName, label+" 玩家名非法", true)
			continue
		}
		key := strings.ToLower(strings.ReplaceAll(entry.UUID, "-", "")) + "/" + strings.ToLower(entry.Name)
		if seen[key] {
			a.add(rel, swfReasonDup, label+" 与前面的条目重复", false)
		}
		seen[key] = true
	}
	return a
}
