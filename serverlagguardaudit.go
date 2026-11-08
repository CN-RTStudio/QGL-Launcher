package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	slgMaxFindings = 16
	slgMaxFile     = 256 * 1024
	slgMiss        = "properties-missing"
	slgRead        = "properties-unreadable"
	slgLink        = "properties-symlink"
	slgEmpty       = "properties-empty"
	slgViewDist    = "view-distance-excessive"
	slgSimDist     = "simulation-distance-excessive"
	slgChain       = "max-chained-neighbor-updates-unbounded"
	slgSyncWrites  = "sync-chunk-writes-off"
	slgTickTime    = "max-tick-time-watchdog-off"
	slgBroadcast   = "entity-broadcast-range-excessive"
)

type LagGuardFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type LagGuardAudit struct {
	ServerDir string
	Findings  []LagGuardFinding
}

func (a *LagGuardAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= slgMaxFindings {
		return
	}
	a.Findings = append(a.Findings, LagGuardFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *LagGuardAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *LagGuardAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *LagGuardAudit) Describe() string {
	return describeAuditFindings("视距与区块写入参数未发现资源耗尽风险", a.Findings, 10,
		func(f LagGuardFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f LagGuardFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func slgReadProps(serverDir string, a *LagGuardAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(slgMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(slgRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(slgLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, slgMaxFile)
	if err != nil {
		a.add(slgRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(slgEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}

func slgInt(props map[string]string, key string) (int, bool, bool) {
	raw, ok := props[key]
	if !ok {
		return 0, false, false
	}
	value, parsed := cfgParseInt(cfgStripQuotes(raw))
	if !parsed {
		return 0, true, false
	}
	return value, true, true
}

func slgBool(props map[string]string, key string) (bool, bool) {
	raw, ok := props[key]
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "on", "yes":
		return true, true
	case "false", "off", "no":
		return false, true
	}
	return false, false
}

func AuditServerLagGuard(serverDir string) *LagGuardAudit {
	a := &LagGuardAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(slgMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := slgReadProps(serverDir, a)
	if !ok {
		return a
	}
	if value, has, parsed := slgInt(props, "view-distance"); has {
		if !parsed {
			a.add(slgViewDist, "view-distance 不是整数", true)
		} else if value > 32 {
			a.add(slgViewDist, fmt.Sprintf("view-distance=%d 超出上限 32，区块加载量失控", value), true)
		} else if value > 10 {
			a.add(slgViewDist, fmt.Sprintf("view-distance=%d 高于建议值 10", value), false)
		}
	}
	if value, has, parsed := slgInt(props, "simulation-distance"); has {
		if !parsed {
			a.add(slgSimDist, "simulation-distance 不是整数", true)
		} else if value > 32 {
			a.add(slgSimDist, fmt.Sprintf("simulation-distance=%d 超出上限 32，实体运算负载过高", value), true)
		} else if value > 10 {
			a.add(slgSimDist, fmt.Sprintf("simulation-distance=%d 高于建议值 10", value), false)
		}
	}
	if value, has, parsed := slgInt(props, "max-chained-neighbor-updates"); has {
		if !parsed {
			a.add(slgChain, "max-chained-neighbor-updates 不是整数", true)
		} else if value < 0 {
			a.add(slgChain, fmt.Sprintf("max-chained-neighbor-updates=%d 关闭链式更新上限，可被用于卡服", value), true)
		} else if value > 100000 {
			a.add(slgChain, fmt.Sprintf("max-chained-neighbor-updates=%d 远高于默认 100000", value), false)
		}
	}
	if value, has := slgBool(props, "sync-chunk-writes"); has && !value {
		a.add(slgSyncWrites, "关闭同步区块写入，崩溃时易丢失或损坏区块", false)
	}
	if value, has, parsed := slgInt(props, "max-tick-time"); has {
		if !parsed {
			a.add(slgTickTime, "max-tick-time 不是整数", true)
		} else if value == -1 {
			a.add(slgTickTime, "max-tick-time=-1 关闭看门狗，单 tick 卡死不会触发保护", false)
		} else if value <= 0 {
			a.add(slgTickTime, fmt.Sprintf("max-tick-time=%d 不是合法正数", value), true)
		} else if value > 60000 {
			a.add(slgTickTime, fmt.Sprintf("max-tick-time=%d 高于 60000 毫秒", value), false)
		}
	}
	if value, has, parsed := slgInt(props, "entity-broadcast-range-percentage"); has {
		if !parsed {
			a.add(slgBroadcast, "entity-broadcast-range-percentage 不是整数", true)
		} else if value <= 0 {
			a.add(slgBroadcast, fmt.Sprintf("entity-broadcast-range-percentage=%d 非正数", value), true)
		} else if value > 100 {
			a.add(slgBroadcast, fmt.Sprintf("entity-broadcast-range-percentage=%d 超出 100，实体包放大", value), false)
		}
	}
	return a
}
