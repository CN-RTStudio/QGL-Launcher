package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	tkReasonOK              = "ok"
	tkReasonMissing         = "missing"
	tkReasonUnreadable      = "unreadable"
	tkReasonSymlink         = "symlink"
	tkReasonWatchdogOff     = "watchdog-disabled"
	tkReasonTickBudget      = "tick-budget"
	tkReasonUnsafeSave      = "unsafe-save"
	tkReasonPlayerLimit     = "player-limit"
	tkReasonCompression     = "compression-threshold"
	tkReasonViewDistance    = "view-distance"
	tkReasonSimulation      = "simulation-distance"
	tkReasonBroadcast       = "broadcast-range"
	tkReasonCollisions      = "entity-collisions"
	tkReasonIdleTimeout     = "idle-timeout"
	tkReasonSpawnProtection = "spawn-protection"
	tkReasonResourcePack    = "required-resource-pack"
	tkReasonLevelName       = "unsafe-level-name"
	tkReasonStatusOff       = "status-hidden"
	tkReasonTooLarge        = "too-large"

	tkMaxPropertiesBytes = 1 << 20
	tkMaxFindings        = 48
	tkMinTickBudget      = 1000
	tkMaxTickBudget      = 600000
	tkMaxPlayersBudget   = 200
	tkMaxViewDistance    = 16
	tkMaxBroadcast       = 200
	tkMaxCollisions      = 8
)

type TickConfigFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type TickConfigAudit struct {
	Dir      string
	File     string
	Props    map[string]string
	Findings []TickConfigFinding
}

func (a TickConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f TickConfigFinding) bool { return f.Blocking })
}

func (a TickConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f TickConfigFinding) bool { return !f.Blocking && f.Reason != tkReasonOK })
}

func (a TickConfigAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == tkReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail))
		if len(parts) >= tkMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务端运行参数未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *TickConfigAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= tkMaxFindings {
		return
	}
	a.Findings = append(a.Findings, TickConfigFinding{
		File:     "server.properties",
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}

func tkInt(props map[string]string, key string, fallback int) int {
	raw, ok := props[key]
	if !ok {
		return fallback
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return value
}

func tkBool(props map[string]string, key string, fallback bool) bool {
	raw, ok := props[key]
	if !ok {
		return fallback
	}
	return strings.EqualFold(strings.TrimSpace(raw), "true")
}

func tkLevelNameSafe(name string) bool {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return false
	}
	if trimmed == "." || trimmed == ".." {
		return false
	}
	if strings.Contains(trimmed, "..") {
		return false
	}
	if strings.ContainsAny(trimmed, "/\\") {
		return false
	}
	if len([]rune(trimmed)) > 64 {
		return false
	}
	return true
}

func AuditServerTickConfig(serverDir string) TickConfigAudit {
	audit := TickConfigAudit{
		Dir:   serverDir,
		File:  filepath.Join(serverDir, "server.properties"),
		Props: map[string]string{},
	}
	info, err := os.Lstat(audit.File)
	if err != nil || info.IsDir() {
		audit.add(tkReasonMissing, "缺少 server.properties", false)
		return audit
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(tkReasonSymlink, "server.properties 是符号链接", true)
		return audit
	}
	if info.Size() > tkMaxPropertiesBytes {
		audit.add(tkReasonTooLarge, "server.properties 超过体积预算", true)
		return audit
	}
	data, err := readBoundedFile(audit.File, tkMaxPropertiesBytes)
	if err != nil {
		audit.add(tkReasonUnreadable, "server.properties 不可读", true)
		return audit
	}
	audit.Props = pxParseProperties(string(data))

	maxTick := tkInt(audit.Props, "max-tick-time", 60000)
	if maxTick < 0 {
		audit.add(tkReasonWatchdogOff, "max-tick-time=-1 关闭了看门狗", true)
	} else if maxTick < tkMinTickBudget {
		audit.add(tkReasonTickBudget, fmt.Sprintf("max-tick-time=%d 过短，容易误杀正常 GC", maxTick), false)
	} else if maxTick > tkMaxTickBudget {
		audit.add(tkReasonTickBudget, fmt.Sprintf("max-tick-time=%d 过长，卡死难以及时重启", maxTick), false)
	}

	if !tkBool(audit.Props, "sync-chunk-writes", true) {
		audit.add(tkReasonUnsafeSave, "sync-chunk-writes=false 崩溃时可能丢失区块写入", false)
	}

	maxPlayers := tkInt(audit.Props, "max-players", 20)
	if maxPlayers <= 0 {
		audit.add(tkReasonPlayerLimit, "max-players 非正数，拒绝所有玩家", true)
	} else if maxPlayers > tkMaxPlayersBudget {
		audit.add(tkReasonPlayerLimit, fmt.Sprintf("max-players=%d 超过预算", maxPlayers), false)
	}

	threshold := tkInt(audit.Props, "network-compression-threshold", 256)
	if threshold < 0 {
		audit.add(tkReasonCompression, "network-compression-threshold=-1 关闭压缩，带宽放大", false)
	} else if threshold > 512 {
		audit.add(tkReasonCompression, fmt.Sprintf("network-compression-threshold=%d 几乎不压缩", threshold), false)
	}

	viewDistance := tkInt(audit.Props, "view-distance", 10)
	if viewDistance < 2 {
		audit.add(tkReasonViewDistance, fmt.Sprintf("view-distance=%d 过小，客户端区块频繁重载", viewDistance), false)
	} else if viewDistance > tkMaxViewDistance {
		audit.add(tkReasonViewDistance, fmt.Sprintf("view-distance=%d 超过预算", viewDistance), false)
	}

	simulation := tkInt(audit.Props, "simulation-distance", viewDistance)
	if simulation <= 0 {
		audit.add(tkReasonSimulation, "simulation-distance 非正数", true)
	} else if simulation > viewDistance {
		audit.add(tkReasonSimulation, fmt.Sprintf("simulation-distance=%d 大于 view-distance=%d", simulation, viewDistance), false)
	}

	broadcast := tkInt(audit.Props, "entity-broadcast-range-percentage", 100)
	if broadcast < 50 || broadcast > tkMaxBroadcast {
		audit.add(tkReasonBroadcast, fmt.Sprintf("entity-broadcast-range-percentage=%d 超出合理区间", broadcast), false)
	}

	collisions := tkInt(audit.Props, "max-entity-collisions", 8)
	if collisions > tkMaxCollisions {
		audit.add(tkReasonCollisions, fmt.Sprintf("max-entity-collisions=%d 过高，实体挤压可拖慢 tick", collisions), false)
	}

	if idle := tkInt(audit.Props, "player-idle-timeout", 0); idle == 0 {
		audit.add(tkReasonIdleTimeout, "player-idle-timeout=0 不会踢出挂机连接", false)
	}

	if spawn := tkInt(audit.Props, "spawn-protection", 16); spawn == 0 {
		audit.add(tkReasonSpawnProtection, "spawn-protection=0 出生点无保护", false)
	}

	if tkBool(audit.Props, "require-resource-pack", false) &&
		strings.TrimSpace(audit.Props["resource-pack"]) == "" {
		audit.add(tkReasonResourcePack, "强制资源包却没有配置下载地址", true)
	}

	if !tkBool(audit.Props, "enable-status", true) {
		audit.add(tkReasonStatusOff, "enable-status=false 隐藏服务器状态", false)
	}

	if !tkLevelNameSafe(audit.Props["level-name"]) {
		audit.add(tkReasonLevelName, fmt.Sprintf("level-name=%q 非法或越界", audit.Props["level-name"]), true)
	}

	if len(audit.Findings) == 0 {
		audit.add(tkReasonOK, "运行参数符合预期", false)
	}
	return audit
}
