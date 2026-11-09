package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func AuditServerUserCache(serverDir string) *UserCacheAudit {
	a := &UserCacheAudit{ServerDir: serverDir}
	const rel = "usercache.json"
	if serverDir == "" {
		a.add(".", sucReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sucReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, sucReasonSymlink, "缓存文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, sucMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, sucReasonTooLarge, fmt.Sprintf("缓存文件超过 %d 字节", sucMaxFile), true)
			return a
		}
		a.add(rel, sucReasonUnread, "缓存文件不可读", false)
		return a
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		a.add(rel, sucReasonParse, "缓存文件为空", true)
		return a
	}
	var entries []UserCacheEntry
	if err := json.Unmarshal([]byte(text), &entries); err != nil {
		a.add(rel, sucReasonParse, "缓存不是合法 JSON 数组", true)
		return a
	}
	if len(entries) == 0 {
		return a
	}
	if len(entries) > sucMaxEntries {
		a.add(rel, sucReasonCount, fmt.Sprintf("缓存条目数 %d 超过上限", len(entries)), true)
	}
	seen := map[string]string{}
	for index, entry := range entries {
		label := fmt.Sprintf("#%d", index)
		name := strings.TrimSpace(entry.Name)
		if !sucNamePattern.MatchString(name) {
			a.add(rel, sucReasonName, label+" 名称非法", true)
		}
		if cfgHasControlChars(name) {
			a.add(rel, sucReasonName, label+" 名称含控制字符", true)
		}
		uuid := strings.ToLower(strings.TrimSpace(entry.UUID))
		if !sucUUIDPattern.MatchString(uuid) {
			a.add(rel, sucReasonUUID, label+" UUID 非法", true)
		} else if previous, exists := seen[uuid]; exists {
			a.add(rel, sucReasonDup, label+" 与 "+previous+" UUID 重复", false)
		} else {
			seen[uuid] = label
		}
		if strings.TrimSpace(entry.ExpiresOn) == "" {
			a.add(rel, sucReasonExpiry, label+" 缺少过期时间", false)
		}
	}
	return a
}
