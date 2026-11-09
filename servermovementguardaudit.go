package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	smaMaxFindings     = 40
	smaMaxProps        = 256 * 1024
	smaMaxWorldSize    = 29999984
	smaMinIdleMinutes  = 5
	smaMaxPlayersSoft  = 200
	smaReasonOK        = "ok"
	smaReasonMissing   = "missing"
	smaReasonSymlink   = "symlink"
	smaReasonTooLarge  = "too-large"
	smaReasonUnread    = "unreadable"
	smaReasonBadValue  = "bad-value"
	smaReasonFlight    = "allow-flight-enabled"
	smaReasonIdle      = "idle-timeout-disabled"
	smaReasonSpawnProt = "spawn-protection-disabled"
	smaReasonWorldSize = "max-world-size-invalid"
	smaReasonPlayerCap = "max-players-oversized"
	smaReasonDebug     = "debug-enabled"
)

type MovementGuardFinding = auditFinding

type MovementGuardAudit struct {
	ServerDir string
	Findings  []MovementGuardFinding
}

func (a *MovementGuardAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= smaMaxFindings {
		return
	}
	a.Findings = append(a.Findings, MovementGuardFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *MovementGuardAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f MovementGuardFinding) bool { return f.Blocking })
}

func (a *MovementGuardAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if f.Reason != smaReasonOK && !f.Blocking {
			return true
		}
	}
	return false
}

func (a *MovementGuardAudit) Describe() string {
	return describeFindings(a.Findings, func(f MovementGuardFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func smaLoadText(a *MovementGuardAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func smaBool(props map[string]string, key string) (bool, bool) {
	return propsLookupBool(props, key)
}

func smaInt(props map[string]string, key string) (int, bool, bool) {
	return propsLookupInt(props, key)
}

func smaCheckProperties(a *MovementGuardAudit, props map[string]string) {
	flight, flightKnown := smaBool(props, "allow-flight")
	if flightKnown && flight {
		a.add("server.properties", smaReasonFlight, "allow-flight=true，客户端可绕过移动校验飞行", false)
	}

	idle, idleKnown, idleValid := smaInt(props, "player-idle-timeout")
	if idleKnown {
		switch {
		case !idleValid:
			a.add("server.properties", smaReasonBadValue, "player-idle-timeout 不是合法整数", false)
		case idle == 0:
			a.add("server.properties", smaReasonIdle, "player-idle-timeout=0，挂机玩家永不被踢出", false)
		case idle < smaMinIdleMinutes:
			a.add("server.properties", smaReasonIdle, fmt.Sprintf("player-idle-timeout=%d 低于 %d 分钟", idle, smaMinIdleMinutes), false)
		}
	}

	spawn, spawnKnown, spawnValid := smaInt(props, "spawn-protection")
	if spawnKnown {
		switch {
		case !spawnValid:
			a.add("server.properties", smaReasonBadValue, "spawn-protection 不是合法整数", false)
		case spawn == 0:
			a.add("server.properties", smaReasonSpawnProt, "spawn-protection=0，出生点保护关闭", false)
		case spawn < 0:
			a.add("server.properties", smaReasonBadValue, fmt.Sprintf("spawn-protection=%d 为负值", spawn), false)
		}
	}

	size, sizeKnown, sizeValid := smaInt(props, "max-world-size")
	if sizeKnown {
		switch {
		case !sizeValid:
			a.add("server.properties", smaReasonWorldSize, "max-world-size 不是合法整数", true)
		case size < 1 || size > smaMaxWorldSize:
			a.add("server.properties", smaReasonWorldSize, fmt.Sprintf("max-world-size=%d 超出 1..%d", size, smaMaxWorldSize), true)
		}
	}

	players, playersKnown, playersValid := smaInt(props, "max-players")
	if playersKnown {
		switch {
		case !playersValid:
			a.add("server.properties", smaReasonBadValue, "max-players 不是合法整数", false)
		case players < 1:
			a.add("server.properties", smaReasonBadValue, fmt.Sprintf("max-players=%d 小于 1", players), false)
		case players > smaMaxPlayersSoft:
			a.add("server.properties", smaReasonPlayerCap, fmt.Sprintf("max-players=%d 高于 %d", players, smaMaxPlayersSoft), false)
		}
	}

	debugOn, debugKnown := smaBool(props, "debug")
	if debugKnown && debugOn {
		a.add("server.properties", smaReasonDebug, "debug=true，输出包含内部路径与堆栈的调试信息", false)
	}
}

func smaCheckPaper(a *MovementGuardAudit, flat map[string]string) {
	if value, ok := cfgLookup(flat, "misc.max-joins-per-tick"); ok {
		n, valid := cfgParseInt(value)
		if !valid {
			a.add("config/paper-global.yml", smaReasonBadValue, "misc.max-joins-per-tick 不是合法整数", false)
			return
		}
		if n < 1 {
			a.add("config/paper-global.yml", smaReasonBadValue, fmt.Sprintf("misc.max-joins-per-tick=%d 小于 1", n), false)
		}
	}
	if value, ok := cfgLookup(flat, "collisions.enable-player-collisions"); ok {
		on, known := spxBool(value)
		if !known {
			a.add("config/paper-global.yml", smaReasonBadValue, "collisions.enable-player-collisions 取值非法: "+value, false)
			return
		}
		if on {
			a.add("config/paper-global.yml", smaReasonFlight, "collisions.enable-player-collisions=true，玩家推挤可绕过移动校验", false)
		}
	}
}

func AuditServerMovementGuards(serverDir string) *MovementGuardAudit {
	a := &MovementGuardAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", smaReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", smaReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", smaReasonMissing, "服务器目录不存在", false)
		return a
	}

	if text, ok := smaLoadText(a, serverDir, "server.properties", smaMaxProps); ok {
		props := pxParseProperties(text)
		if len(props) == 0 && strings.TrimSpace(text) != "" {
			a.add("server.properties", smaReasonBadValue, "server.properties 未解析出任何键值", false)
		}
		smaCheckProperties(a, props)
	}

	if text, ok := smaLoadText(a, serverDir, filepath.Join("config", "paper-global.yml"), smaMaxProps); ok {
		smaCheckPaper(a, cfgFlattenYAML(text))
	}

	if len(a.Findings) == 0 {
		a.add("server.properties", smaReasonOK, "未发现移动与容量相关配置", false)
	}
	return a
}
