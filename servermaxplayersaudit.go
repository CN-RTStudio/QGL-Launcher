package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	smpMaxFindings = 14
	smpReasonCount = "max-players-invalid"
	smpReasonMany  = "max-players-too-high"
	smpReasonIdle  = "idle-timeout-disabled"
	smpReasonRate  = "rate-limit-disabled"
	smpReasonView  = "view-distance-out-of-range"
	smpReasonSim   = "simulation-distance-out-of-range"
)

type MaxPlayersFinding struct {
	Reason   string
	Detail   string
	Blocking bool
}

type MaxPlayersAudit struct {
	ServerDir string
	Findings  []MaxPlayersFinding
}

func (a *MaxPlayersAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= smpMaxFindings {
		return
	}
	a.Findings = append(a.Findings, MaxPlayersFinding{Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *MaxPlayersAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *MaxPlayersAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *MaxPlayersAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "容量与限流配置未发现风险"
	}
	sorted := make([]MaxPlayersFinding, len(a.Findings))
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

func AuditServerMaxPlayers(serverDir string) *MaxPlayersAudit {
	a := &MaxPlayersAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(smpReasonCount, "未配置服务器目录", false)
		return a
	}
	data, err := readBoundedFile(filepath.Join(serverDir, "server.properties"), 256*1024)
	if err != nil {
		a.add(smpReasonCount, "无法读取 server.properties", false)
		return a
	}
	props := pxParseProperties(string(data))
	if len(props) == 0 {
		a.add(smpReasonCount, "属性文件为空", false)
		return a
	}
	if raw, ok := props["max-players"]; ok {
		value, parsed := cfgParseInt(raw)
		switch {
		case !parsed || value <= 0:
			a.add(smpReasonCount, "max-players 非法: "+cfgStripQuotes(raw), true)
		case value > 200:
			a.add(smpReasonMany, "max-players="+strconv.Itoa(value)+" 超出单机承载", false)
		}
	}
	if raw, ok := props["player-idle-timeout"]; ok {
		value, parsed := cfgParseInt(raw)
		if !parsed || value <= 0 {
			a.add(smpReasonIdle, "空闲踢出已关闭，连接可长期挂起", false)
		}
	}
	if raw, ok := props["rate-limit"]; ok {
		value, parsed := cfgParseInt(raw)
		if !parsed || value <= 0 {
			a.add(smpReasonRate, "报文限流为 0，洪水攻击无制动", false)
		}
	}
	if raw, ok := props["view-distance"]; ok {
		value, parsed := cfgParseInt(raw)
		if !parsed || value < 3 || value > 32 {
			a.add(smpReasonView, "view-distance="+cfgStripQuotes(raw), false)
		}
	}
	if raw, ok := props["simulation-distance"]; ok {
		value, parsed := cfgParseInt(raw)
		if !parsed || value < 3 || value > 32 {
			a.add(smpReasonSim, "simulation-distance="+cfgStripQuotes(raw), false)
		}
	}
	if raw, ok := props["max-world-size"]; ok {
		if value, parsed := cfgParseInt(raw); !parsed || value <= 0 {
			a.add(smpReasonView, "世界尺寸上限非法: "+cfgStripQuotes(raw), false)
		}
	}
	return a
}
