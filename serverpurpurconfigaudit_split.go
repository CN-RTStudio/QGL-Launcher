package main

import (
	"os"
	"path/filepath"
	"strings"
)

func AuditServerPurpurConfig(serverDir string) *PurpurAudit {
	a := &PurpurAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("purpur.yml", spqReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "purpur.yml"
	path := filepath.Join(serverDir, rel)
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, spqReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, spqReasonLink, "配置是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, spqReasonMiss, "未找到 purpur.yml", false)
		return a
	}
	data, err := readBoundedFile(path, spqMaxFile)
	if err != nil {
		reason := spqReasonRead
		if err == errLocalFileTooLarge {
			reason = spqReasonLarge
		}
		a.add(rel, reason, err.Error(), true)
		return a
	}
	text := string(data)
	if strings.TrimSpace(text) == "" {
		a.add(rel, spqReasonEmpty, "配置文件为空", false)
		return a
	}
	flat := cfgFlattenYAML(text)
	if len(flat) == 0 {
		a.add(rel, spqReasonEmpty, "配置无法解析", false)
		return a
	}

	openReduced := false
	for key, raw := range flat {
		value := strings.ToLower(cfgStripQuotes(raw))
		if strings.Contains(key, "messages") && cfgHasControlChars(raw) {
			a.add(rel, spqReasonMsg, key, true)
		}
		if strings.HasSuffix(key, "tps-catchup") && value == "false" {
			a.add(rel, spqReasonRate, key, false)
		}
		if strings.Contains(key, "allow-grindstone") && value == "true" {
			openReduced = true
		}
		if strings.Contains(key, "allow-player-inventory-lookup") && value == "true" {
			a.add(rel, spqReasonAllow, key, false)
		}
		if strings.Contains(key, "player.teleport-invulnerability") {
			if n, ok := cfgParseInt(raw); ok && n <= 0 {
				a.add(rel, spqReasonRate, "传送保护时长为 0", false)
			}
		}
		if strings.HasSuffix(key, "join.limit") || strings.HasSuffix(key, "joins.limit") {
			if n, ok := cfgParseInt(raw); ok && n <= 0 {
				a.add(rel, spqReasonJoin, key, false)
			}
		}
		if strings.Contains(key, "bypass") && strings.Contains(key, "permission") && value == "true" {
			a.add(rel, spqReasonOps, key, false)
		}
		if strings.HasPrefix(key, "settings.messages.") && len(key) > 96 {
			a.add(rel, spqReasonMsg, "消息键过长", false)
		}
	}
	if openReduced {
		a.add(rel, spqReasonAllow, "允许玩家使用砂轮修补", false)
	}
	if len(flat) > 4000 {
		a.add(rel, spqReasonDep, "配置项超过 4000", false)
	}
	return a
}
