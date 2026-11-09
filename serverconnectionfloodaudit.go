package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	cfdMaxFindings      = 48
	cfdMaxProps         = 256 * 1024
	cfdMaxYAML          = 512 * 1024
	cfdThrottleMin      = 1
	cfdThrottleMax      = 10000
	cfdTimeoutMax       = 600
	cfdJoinBurstMax     = 10
	cfdMaxPlayersMax    = 200
	cfdReasonOK         = "ok"
	cfdReasonMissing    = "missing"
	cfdReasonSymlink    = "symlink"
	cfdReasonTooLarge   = "too-large"
	cfdReasonUnreadable = "unreadable"
	cfdReasonBadConfig  = "bad-config"
	cfdReasonBadValue   = "bad-value"
	cfdThrottleOff      = "throttle-disabled"
	cfdThrottleLoose    = "throttle-loose"
	cfdTimeoutLoose     = "slow-timeout"
	cfdJoinBurst        = "join-burst"
	cfdPlayersBulk      = "max-players-large"
	cfdRateLimitOff     = "rate-limit-disabled"
	cfdConflict         = "duplicate-setting"
)

type ConnectionFloodFinding = auditFinding

type ConnectionFloodAudit struct {
	ServerDir string
	Findings  []ConnectionFloodFinding
}

func (a *ConnectionFloodAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, cfdMaxFindings, ConnectionFloodFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *ConnectionFloodAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ConnectionFloodFinding) bool { return f.Blocking })
}

func (a *ConnectionFloodAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f ConnectionFloodFinding) bool { return f.Reason != cfdReasonOK && !f.Blocking })
}

func (a *ConnectionFloodAudit) Describe() string {
	return describeFindings(a.Findings, func(f ConnectionFloodFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func cfdLoad(a *ConnectionFloodAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func cfdIntField(a *ConnectionFloodAudit, file, label, value string) (int, bool) {
	n, ok := cfgParseInt(value)
	if !ok {
		a.add(file, cfdReasonBadValue, label+" 不是合法整数: "+value, false)
		return 0, false
	}
	return n, true
}

func cfdCheckThrottle(a *ConnectionFloodAudit, file string, flat map[string]string) {
	value, ok := cfgLookup(flat, "settings.connection-throttle")
	if !ok {
		return
	}
	n, valid := cfdIntField(a, file, "connection-throttle", value)
	if !valid {
		return
	}
	if n < cfdThrottleMin {
		a.add(file, cfdThrottleOff, fmt.Sprintf("connection-throttle=%d 关闭了重连节流，可被快速重连放大", n), true)
		return
	}
	if n > cfdThrottleMax {
		a.add(file, cfdThrottleLoose, fmt.Sprintf("connection-throttle=%d 超过 %d 毫秒", n, cfdThrottleMax), false)
	}
}

func cfdCheckSpigot(a *ConnectionFloodAudit, flat map[string]string) {
	if value, ok := cfgLookup(flat, "settings.timeout-time"); ok {
		n, valid := cfdIntField(a, "spigot.yml", "settings.timeout-time", value)
		if valid {
			if n <= 0 {
				a.add("spigot.yml", cfdReasonBadValue, fmt.Sprintf("settings.timeout-time=%d 不是正数", n), false)
			} else if n > cfdTimeoutMax {
				a.add("spigot.yml", cfdTimeoutLoose, fmt.Sprintf("settings.timeout-time=%d 超过 %d 秒，慢连接占用时间过长", n, cfdTimeoutMax), false)
			}
		}
	}
	if value, ok := cfgLookup(flat, "settings.player-shuffle"); ok {
		n, valid := cfdIntField(a, "spigot.yml", "settings.player-shuffle", value)
		if valid && n < 0 {
			a.add("spigot.yml", cfdReasonBadValue, fmt.Sprintf("settings.player-shuffle=%d 为负数", n), false)
		}
	}
	if value, ok := cfgLookup(flat, "settings.connection-throttle"); ok {
		n, valid := cfdIntField(a, "spigot.yml", "settings.connection-throttle", value)
		if valid && n < cfdThrottleMin {
			a.add("spigot.yml", cfdThrottleOff, fmt.Sprintf("settings.connection-throttle=%d 关闭了重连节流", n), true)
		}
	}
}

func cfdCheckPaper(a *ConnectionFloodAudit, flat map[string]string) {
	if value, ok := cfgLookup(flat, "misc.max-joins-per-tick"); ok {
		n, valid := cfdIntField(a, "config/paper-global.yml", "misc.max-joins-per-tick", value)
		if valid {
			if n <= 0 {
				a.add("config/paper-global.yml", cfdReasonBadValue, fmt.Sprintf("misc.max-joins-per-tick=%d 不是正数", n), false)
			} else if n > cfdJoinBurstMax {
				a.add("config/paper-global.yml", cfdJoinBurst, fmt.Sprintf("misc.max-joins-per-tick=%d 超过 %d，登录洪峰可拖慢主线程", n, cfdJoinBurstMax), false)
			}
		}
	}
	if value, ok := cfgLookup(flat, "misc.player-auto-save-interval"); ok {
		n, valid := cfdIntField(a, "config/paper-global.yml", "misc.player-auto-save-interval", value)
		if valid && n <= 0 {
			a.add("config/paper-global.yml", cfdReasonBadValue, "misc.player-auto-save-interval 关闭了自动保存", false)
		}
	}
}

func cfdCheckProperties(a *ConnectionFloodAudit, props map[string]string) {
	if value, ok := props["max-players"]; ok {
		n, valid := cfdIntField(a, "server.properties", "max-players", value)
		if valid {
			if n < 0 {
				a.add("server.properties", cfdReasonBadValue, fmt.Sprintf("max-players=%d 为负数", n), false)
			} else if n > cfdMaxPlayersMax {
				a.add("server.properties", cfdPlayersBulk, fmt.Sprintf("max-players=%d 超过 %d，登录与实体负载偏高", n, cfdMaxPlayersMax), false)
			}
		}
	}
	if value, ok := props["rate-limit"]; ok {
		n, valid := cfdIntField(a, "server.properties", "rate-limit", value)
		if valid && n == 0 {
			a.add("server.properties", cfdRateLimitOff, "rate-limit=0 关闭了数据包速率上限", false)
		}
	}
	if value, ok := props["player-idle-timeout"]; ok {
		n, valid := cfdIntField(a, "server.properties", "player-idle-timeout", value)
		if valid && n == 0 {
			a.add("server.properties", cfdTimeoutLoose, "player-idle-timeout=0 永不踢出空闲连接", false)
		}
	}
}

func cfdCheckThrottleConflict(a *ConnectionFloodAudit, props map[string]string, spigotFlat, bukkitFlat map[string]string) {
	spigotValue, hasSpigot := cfgLookup(spigotFlat, "settings.connection-throttle")
	bukkitValue, hasBukkit := cfgLookup(bukkitFlat, "settings.connection-throttle")
	if !hasSpigot || !hasBukkit {
		return
	}
	if strings.TrimSpace(spigotValue) != strings.TrimSpace(bukkitValue) {
		a.add("spigot.yml", cfdConflict, fmt.Sprintf("connection-throttle 与 bukkit.yml 不一致: %s / %s", spigotValue, bukkitValue), false)
	}
}

func AuditServerConnectionFlood(serverDir string) *ConnectionFloodAudit {
	a := &ConnectionFloodAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", cfdReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", cfdReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", cfdReasonMissing, "服务器目录不存在", false)
		return a
	}

	props := map[string]string{}
	if text, ok := cfdLoad(a, serverDir, "server.properties", cfdMaxProps); ok {
		props = pxParseProperties(text)
		if len(props) == 0 && strings.TrimSpace(text) != "" {
			a.add("server.properties", cfdReasonBadConfig, "server.properties 未解析出任何键值", false)
		}
		cfdCheckProperties(a, props)
	}

	bukkitFlat := map[string]string{}
	if text, ok := cfdLoad(a, serverDir, "bukkit.yml", cfdMaxYAML); ok {
		bukkitFlat = cfgFlattenYAML(text)
		cfdCheckThrottle(a, "bukkit.yml", bukkitFlat)
	}

	spigotFlat := map[string]string{}
	if text, ok := cfdLoad(a, serverDir, "spigot.yml", cfdMaxYAML); ok {
		spigotFlat = cfgFlattenYAML(text)
		cfdCheckSpigot(a, spigotFlat)
	}

	paperFlat := map[string]string{}
	if text, ok := cfdLoad(a, serverDir, "config/paper-global.yml", cfdMaxYAML); ok {
		paperFlat = cfgFlattenYAML(text)
		cfdCheckPaper(a, paperFlat)
	}

	if len(spigotFlat) > 0 && len(bukkitFlat) > 0 {
		cfdCheckThrottleConflict(a, props, spigotFlat, bukkitFlat)
	}

	if len(props) == 0 && len(bukkitFlat) == 0 && len(spigotFlat) == 0 && len(paperFlat) == 0 {
		a.add(".", cfdReasonMissing, "未发现连接节流相关配置", false)
	}
	return a
}
