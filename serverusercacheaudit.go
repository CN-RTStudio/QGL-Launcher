package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	sucMaxFindings    = 36
	sucMaxFile        = 512 * 1024
	sucMaxEntries     = 8192
	sucReasonOK       = "ok"
	sucReasonMissing  = "missing"
	sucReasonSymlink  = "symlink"
	sucReasonTooLarge = "too-large"
	sucReasonUnread   = "unreadable"
	sucReasonParse    = "invalid-json"
	sucReasonShape    = "invalid-shape"
	sucReasonCount    = "too-many-entries"
	sucReasonUUID     = "invalid-uuid"
	sucReasonName     = "invalid-name"
	sucReasonDup      = "duplicate-uuid"
	sucReasonExpiry   = "invalid-expiry"
)

var sucUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var sucNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)

type UserCacheEntry struct {
	Name      string `json:"name"`
	UUID      string `json:"uuid"`
	ExpiresOn string `json:"expiresOn"`
}

type UserCacheFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type UserCacheAudit struct {
	ServerDir string
	Findings  []UserCacheFinding
}

func (a *UserCacheAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= sucMaxFindings {
		return
	}
	a.Findings = append(a.Findings, UserCacheFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *UserCacheAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f UserCacheFinding) bool { return f.Blocking })
}

func (a *UserCacheAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *UserCacheAudit) Describe() string {
	return describeAuditFindings("玩家缓存未发现风险", a.Findings, 12,
		func(f UserCacheFinding) []string {
			return []string{f.File, f.Reason, f.Detail}
		},
		func(f UserCacheFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

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
