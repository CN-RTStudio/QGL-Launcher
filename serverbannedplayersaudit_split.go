package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func AuditServerBannedPlayers(serverDir string) *BannedPlayerAudit {
	a := &BannedPlayerAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("banned-players.json", sbpReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "banned-players.json"
	path := filepath.Join(serverDir, rel)
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, sbpReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, sbpReasonLink, "封禁名单是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, sbpReasonMiss, "未找到封禁名单", false)
		return a
	}
	data, err := readBoundedFile(path, sbpMaxFile)
	if err != nil {
		reason := sbpReasonRead
		if err == errLocalFileTooLarge {
			reason = sbpReasonLarge
		}
		a.add(rel, reason, err.Error(), true)
		return a
	}
	var entries []sbpEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		a.add(rel, sbpReasonShape, "JSON 结构非法", true)
		return a
	}
	if len(entries) > sbpMaxEntries {
		a.add(rel, sbpReasonLargeN, fmt.Sprintf("条目数 %d 超过上限", len(entries)), false)
	}
	seen := map[string]bool{}
	permanent := 0
	for i, e := range entries {
		detail := fmt.Sprintf("第 %d 条", i+1)
		uuid := strings.ToLower(strings.TrimSpace(e.UUID))
		if !sbpUUIDPattern.MatchString(uuid) {
			a.add(rel, sbpReasonUUID, detail+" uuid 非法", false)
		} else if seen[uuid] {
			a.add(rel, sbpReasonDup, detail+" uuid 重复", true)
		} else {
			seen[uuid] = true
		}
		if !sbpNamePattern.MatchString(e.Name) {
			a.add(rel, sbpReasonName, detail+" 玩家名非法", false)
		}
		if !sbpParseTime(e.Created) || !sbpParseTime(e.Expires) {
			a.add(rel, sbpReasonTime, detail+" 时间戳非法", false)
		}
		if e.Expires == "" || e.Expires == "forever" || e.Expires == "infinite" {
			permanent++
		}
		if cfgHasControlChars(e.Reason) || cfgHasControlChars(e.Source) {
			a.add(rel, sbpReasonReason, detail+" 附注含控制字符", false)
		}
	}
	if permanent > 50 {
		a.add(rel, sbpReasonPerm, fmt.Sprintf("永久封禁 %d 条", permanent), false)
	}
	return a
}
