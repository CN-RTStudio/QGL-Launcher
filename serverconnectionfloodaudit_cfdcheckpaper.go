package main

import (
	"fmt"
	"strings"
)

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
