package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func AuditServerBannedIPs(serverDir string) *BannedIPAudit {
	a := &BannedIPAudit{ServerDir: serverDir}
	const rel = "banned-ips.json"
	if serverDir == "" {
		a.add(".", sbiReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sbiReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, sbiReasonSymlink, "封禁清单为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, sbiMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, sbiReasonTooLarge, fmt.Sprintf("封禁清单超过 %d 字节", sbiMaxFile), true)
			return a
		}
		a.add(rel, sbiReasonUnread, "封禁清单不可读", false)
		return a
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		a.add(rel, sbiReasonParse, "封禁清单为空", true)
		return a
	}
	var entries []BannedIPEntry
	if err := json.Unmarshal([]byte(text), &entries); err != nil {
		a.add(rel, sbiReasonParse, "封禁清单不是合法 JSON 数组", true)
		return a
	}
	if len(entries) == 0 {
		return a
	}
	if len(entries) > sbiMaxEntries {
		a.add(rel, sbiReasonCount, fmt.Sprintf("封禁条目 %d 超过上限", len(entries)), true)
	}
	seen := map[string]string{}
	for index, entry := range entries {
		label := fmt.Sprintf("#%d", index)
		address := strings.TrimSpace(entry.IP)
		if !sbiValidAddress(address) {
			a.add(rel, sbiReasonAddress, label+" IP 地址非法", true)
			continue
		}
		normalized := strings.ToLower(address)
		if net.ParseIP(normalized) != nil {
			normalized = net.ParseIP(normalized).String()
		}
		if previous, exists := seen[normalized]; exists {
			a.add(rel, sbiReasonDup, label+" 与 "+previous+" 重复", false)
		} else {
			seen[normalized] = label
		}
		if strings.TrimSpace(entry.Expires) == "" && strings.TrimSpace(entry.Created) == "" {
			a.add(rel, sbiReasonExpiry, label+" 缺少封禁时间信息", false)
		}
		if cfgHasControlChars(entry.Source) {
			a.add(rel, sbiReasonAddress, label+" 来源字段含控制字符", true)
		}
	}
	return a
}

const (
	sbpMaxFindings  = 32
	sbpMaxFile      = 512 * 1024
	sbpMaxEntries   = 2000
	sbpReasonMiss   = "missing"
	sbpReasonLink   = "symlink"
	sbpReasonLarge  = "too-large"
	sbpReasonRead   = "unreadable"
	sbpReasonShape  = "invalid-shape"
	sbpReasonLargeN = "too-many-entries"
	sbpReasonUUID   = "invalid-uuid"
	sbpReasonName   = "invalid-name"
	sbpReasonTime   = "invalid-timestamp"
	sbpReasonReason = "unsafe-reason"
	sbpReasonDup    = "duplicate-uuid"
	sbpReasonPerm   = "many-permanent-bans"
)

type BannedPlayerFinding = auditFinding

type BannedPlayerAudit struct {
	ServerDir string
	Findings  []BannedPlayerFinding
}
