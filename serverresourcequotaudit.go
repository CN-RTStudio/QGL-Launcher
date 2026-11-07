package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	srqMaxFindings = 16
	srqMaxFile     = 256 * 1024
	srqMiss        = "properties-missing"
	srqRead        = "properties-unreadable"
	srqLink        = "properties-symlink"
	srqEmpty       = "properties-empty"
	srqMaxPlayers  = "max-players-invalid"
	srqCollisions  = "max-entity-collisions-excessive"
	srqWorldSize   = "max-world-size-invalid"
	srqSpawnGuard  = "spawn-protection-excessive"
	srqIdleBound   = "player-idle-timeout-out-of-range"
	srqCompressBig = "network-compression-threshold-ineffective"
	srqPauseIdle   = "pause-when-empty-seconds-excessive"
)

type ResourceQuotaFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type ResourceQuotaAudit struct {
	ServerDir string
	Findings  []ResourceQuotaFinding
}

func (a *ResourceQuotaAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= srqMaxFindings {
		return
	}
	a.Findings = append(a.Findings, ResourceQuotaFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *ResourceQuotaAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *ResourceQuotaAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *ResourceQuotaAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "玩家与实体配额处于安全区间"
	}
	sorted := make([]ResourceQuotaFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Detail < sorted[j].Detail
	})
	var b strings.Builder
	for i, f := range sorted {
		if i >= 10 {
			b.WriteString(fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		if i > 0 {
			b.WriteString("；")
		}
		b.WriteString(f.Reason)
		if f.Detail != "" {
			b.WriteString("(")
			b.WriteString(f.Detail)
			b.WriteString(")")
		}
	}
	return b.String()
}

func srqReadProps(serverDir string, a *ResourceQuotaAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(srqMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(srqRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(srqLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, srqMaxFile)
	if err != nil {
		a.add(srqRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(srqEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}

func srqInt(props map[string]string, key string) (int, bool, bool) {
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

func AuditServerResourceQuota(serverDir string) *ResourceQuotaAudit {
	a := &ResourceQuotaAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(srqMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := srqReadProps(serverDir, a)
	if !ok {
		return a
	}
	if value, has, parsed := srqInt(props, "max-players"); has {
		if !parsed {
			a.add(srqMaxPlayers, "max-players 不是整数", true)
		} else if value < 1 || value > 200 {
			a.add(srqMaxPlayers, fmt.Sprintf("max-players=%d 超出 1..200", value), true)
		}
	}
	if value, has, parsed := srqInt(props, "max-entity-collisions"); has {
		if !parsed {
			a.add(srqCollisions, "max-entity-collisions 不是整数", true)
		} else if value > 50 {
			a.add(srqCollisions, fmt.Sprintf("max-entity-collisions=%d 高于默认 8", value), false)
		} else if value < 0 {
			a.add(srqCollisions, fmt.Sprintf("max-entity-collisions=%d 为负值", value), true)
		}
	}
	if value, has, parsed := srqInt(props, "max-world-size"); has {
		if !parsed {
			a.add(srqWorldSize, "max-world-size 不是整数", true)
		} else if value < 1000 || value > 29999984 {
			a.add(srqWorldSize, fmt.Sprintf("max-world-size=%d 超出 1000..29999984", value), true)
		}
	}
	if value, has, parsed := srqInt(props, "spawn-protection"); has {
		if !parsed {
			a.add(srqSpawnGuard, "spawn-protection 不是整数", true)
		} else if value > 32 {
			a.add(srqSpawnGuard, fmt.Sprintf("spawn-protection=%d 超出建议值 16", value), false)
		} else if value < 0 {
			a.add(srqSpawnGuard, fmt.Sprintf("spawn-protection=%d 为负值", value), true)
		}
	}
	if value, has, parsed := srqInt(props, "player-idle-timeout"); has {
		if !parsed {
			a.add(srqIdleBound, "player-idle-timeout 不是整数", true)
		} else if value > 1440 {
			a.add(srqIdleBound, fmt.Sprintf("player-idle-timeout=%d 超过一天", value), false)
		}
	}
	if value, has, parsed := srqInt(props, "network-compression-threshold"); has {
		if !parsed {
			a.add(srqCompressBig, "network-compression-threshold 不是整数", true)
		} else if value > 1024 {
			a.add(srqCompressBig, fmt.Sprintf("network-compression-threshold=%d 压缩收益过低", value), false)
		}
	}
	if value, has, parsed := srqInt(props, "pause-when-empty-seconds"); has {
		if !parsed {
			a.add(srqPauseIdle, "pause-when-empty-seconds 不是整数", true)
		} else if value > 3600 {
			a.add(srqPauseIdle, fmt.Sprintf("pause-when-empty-seconds=%d 超过一小时", value), false)
		} else if value < 0 {
			a.add(srqPauseIdle, fmt.Sprintf("pause-when-empty-seconds=%d 为负值", value), true)
		}
	}
	return a
}
