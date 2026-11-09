package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func AuditServerPaperConfig(serverDir string) *PaperAudit {
	a := &PaperAudit{ServerDir: serverDir}
	const rel = "config/paper-global.yml"
	if serverDir == "" {
		a.add(".", pacReasonMiss, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", pacReasonLink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, filepath.FromSlash(rel))
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, pacReasonLink, "Paper 全局配置为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, pacMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, pacReasonLarge, fmt.Sprintf("Paper 全局配置超过 %d 字节", pacMaxFile), true)
			return a
		}
		a.add(rel, pacReasonRead, "Paper 全局配置不可读", false)
		return a
	}
	cfg := cfgFlattenYAML(string(data))
	if len(cfg) == 0 {
		a.add(rel, pacReasonEmpty, "Paper 全局配置为空或格式不可识别", false)
		return a
	}

	velocityEnabled := false
	if value, found := cfgLookup(cfg, "proxies.velocity.enabled"); found {
		velocityEnabled = pacParseBool(cfgStripQuotes(value))
	}
	if velocityEnabled {
		secret := ""
		if value, found := cfgLookup(cfg, "proxies.velocity.secret"); found {
			secret = cfgStripQuotes(value)
		}
		if pacSecretWeak(secret) {
			a.add(rel, pacReasonSecret, "Velocity 转发密钥为空、过短或使用占位值", true)
		}
		if value, found := cfgLookup(cfg, "proxies.velocity.online-mode"); found && !pacParseBool(cfgStripQuotes(value)) {
			a.add(rel, pacReasonOffline, "Velocity 在线模式关闭，可伪造玩家身份", false)
		}
	}
	for _, key := range []string{"proxies.bungee-cord.online-mode", "proxies.bungeecord.online-mode"} {
		if value, found := cfgLookup(cfg, key); found && !pacParseBool(cfgStripQuotes(value)) {
			a.add(rel, pacReasonOffline, "BungeeCord 在线模式关闭，可伪造玩家身份", false)
			break
		}
	}
	if value, found := cfgLookup(cfg, "messages.kick"); found {
		message := cfgStripQuotes(value)
		if pacHasControlChars(message) {
			a.add(rel, pacReasonKick, "踢出提示语含控制字符", true)
		}
	}
	if value, found := cfgLookup(cfg, "chunk-loading.max-concurrent-sends"); found {
		if sends, parsed := cfgParseInt(cfgStripQuotes(value)); parsed && sends > pacMaxSends {
			a.add(rel, pacReasonSends, fmt.Sprintf("并发区块发送上限 %d 超过 %d", sends, pacMaxSends), false)
		}
	}
	if value, found := cfgLookup(cfg, "misc.max-joins-per-tick"); found {
		if joins, parsed := cfgParseInt(cfgStripQuotes(value)); parsed && joins > pacMaxJoins {
			a.add(rel, pacReasonJoins, fmt.Sprintf("每刻加入上限 %d 超过 %d", joins, pacMaxJoins), false)
		}
	}
	if value, found := cfgLookup(cfg, "collisions.enable-player-collisions"); found && !pacParseBool(cfgStripQuotes(value)) {
		a.add(rel, pacReasonCollide, "玩家碰撞检测被关闭", false)
	}
	return a
}
