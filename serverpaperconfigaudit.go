package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	pacMaxFindings   = 36
	pacMaxFile       = 256 * 1024
	pacMinSecret     = 12
	pacMaxSends      = 100
	pacMaxJoins      = 50
	pacReasonMiss    = "missing"
	pacReasonLink    = "symlink"
	pacReasonLarge   = "too-large"
	pacReasonRead    = "unreadable"
	pacReasonEmpty   = "empty-config"
	pacReasonSecret  = "velocity-secret-weak"
	pacReasonOffline = "proxy-offline-mode"
	pacReasonKick    = "unsafe-kick-message"
	pacReasonSends   = "chunk-send-budget-too-high"
	pacReasonJoins   = "join-budget-too-high"
	pacReasonCollide = "player-collisions-disabled"
)

type PaperFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type PaperAudit struct {
	ServerDir string
	Findings  []PaperFinding
}

func (a *PaperAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= pacMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PaperFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PaperAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PaperFinding) bool { return f.Blocking })
}

func (a *PaperAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PaperAudit) Describe() string {
	return describeAuditFindings("Paper 全局配置未发现风险", a.Findings, 12,
		func(f PaperFinding) []string {
			return []string{f.File, f.Reason, f.Detail}
		},
		func(f PaperFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

func pacHasControlChars(text string) bool {
	return hasControlCharsText(text)
}

func pacParseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true
	}
	return false
}

func pacSecretWeak(secret string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(secret))
	if trimmed == "" || len(trimmed) < pacMinSecret {
		return true
	}
	for _, placeholder := range []string{"changeme", "change-me", "secret", "password", "your-secret", "<secret>", "velocity-secret"} {
		if trimmed == placeholder || strings.HasPrefix(trimmed, placeholder) {
			return true
		}
	}
	return false
}

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
