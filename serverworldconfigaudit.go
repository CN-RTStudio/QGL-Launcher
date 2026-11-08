package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	swpMaxFindings = 16
	swpMaxFile     = 256 * 1024
	swpMiss        = "properties-missing"
	swpRead        = "properties-unreadable"
	swpLink        = "properties-symlink"
	swpEmpty       = "properties-empty"
	swpWorldSize   = "max-world-size-invalid"
	swpSpawn       = "spawn-protection-open"
	swpFlight      = "allow-flight-enabled"
	swpViewDist    = "view-distance-invalid"
	swpSimDist     = "simulation-distance-invalid"
	swpTickTime    = "max-tick-time-disabled"
	swpBroadcast   = "entity-broadcast-range-invalid"
)

type WorldConfigFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type WorldConfigAudit struct {
	ServerDir string
	Findings  []WorldConfigFinding
}

func (a *WorldConfigAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= swpMaxFindings {
		return
	}
	a.Findings = append(a.Findings, WorldConfigFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WorldConfigAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *WorldConfigAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *WorldConfigAudit) Describe() string {
	return describeAuditFindings("世界与实体范围配置处于安全区间", a.Findings, 10,
		func(f WorldConfigFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f WorldConfigFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func swpReadProps(serverDir string, a *WorldConfigAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(swpMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(swpRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(swpLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, swpMaxFile)
	if err != nil {
		a.add(swpRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(swpEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}

func swpInt(props map[string]string, key string) (int, bool, bool) {
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

func swpBool(props map[string]string, key string) (bool, bool) {
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

func AuditServerWorldConfig(serverDir string) *WorldConfigAudit {
	a := &WorldConfigAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(swpMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := swpReadProps(serverDir, a)
	if !ok {
		return a
	}
	if value, has, parsed := swpInt(props, "max-world-size"); has {
		if !parsed {
			a.add(swpWorldSize, "max-world-size 不是整数", true)
		} else if value < 1 || value > 29999984 {
			a.add(swpWorldSize, fmt.Sprintf("max-world-size=%d 超出 1..29999984", value), true)
		}
	}
	if value, has, parsed := swpInt(props, "spawn-protection"); has {
		if !parsed {
			a.add(swpSpawn, "spawn-protection 不是整数", true)
		} else if value == 0 {
			a.add(swpSpawn, "spawn-protection=0 出生点无保护", false)
		} else if value > 10000 {
			a.add(swpSpawn, fmt.Sprintf("spawn-protection=%d 过大", value), false)
		}
	}
	if value, has := swpBool(props, "allow-flight"); has && value {
		a.add(swpFlight, "allow-flight=true 允许飞行绕过限制", false)
	}
	if value, has, parsed := swpInt(props, "view-distance"); has {
		if !parsed {
			a.add(swpViewDist, "view-distance 不是整数", true)
		} else if value < 2 || value > 32 {
			a.add(swpViewDist, fmt.Sprintf("view-distance=%d 超出 2..32", value), false)
		}
	}
	if value, has, parsed := swpInt(props, "simulation-distance"); has {
		if !parsed {
			a.add(swpSimDist, "simulation-distance 不是整数", true)
		} else if value < 2 || value > 32 {
			a.add(swpSimDist, fmt.Sprintf("simulation-distance=%d 超出 2..32", value), false)
		}
	}
	if value, has, parsed := swpInt(props, "max-tick-time"); has {
		if !parsed {
			a.add(swpTickTime, "max-tick-time 不是整数", true)
		} else if value < 0 {
			a.add(swpTickTime, "max-tick-time<0 关闭看门狗", false)
		}
	}
	if value, has, parsed := swpInt(props, "entity-broadcast-range-percentage"); has {
		if !parsed {
			a.add(swpBroadcast, "entity-broadcast-range-percentage 不是整数", true)
		} else if value < 10 || value > 1000 {
			a.add(swpBroadcast, fmt.Sprintf("entity-broadcast-range-percentage=%d 超出 10..1000", value), true)
		}
	}
	return a
}
