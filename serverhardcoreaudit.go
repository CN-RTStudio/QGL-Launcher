package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	shcMaxFindings   = 16
	shcReasonHard    = "hardcore-difficulty-mismatch"
	shcReasonPVP     = "hardcore-with-pvp-off"
	shcReasonGamemod = "gamemode-invalid"
	shcReasonForce   = "force-gamemode-off"
	shcReasonSpawn   = "spawn-protection-disabled"
	shcReasonDiff    = "difficulty-invalid"
)

type HardcoreFinding struct {
	Reason   string
	Detail   string
	Blocking bool
}

type HardcoreAudit struct {
	ServerDir string
	Findings  []HardcoreFinding
}

func (a *HardcoreAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= shcMaxFindings {
		return
	}
	a.Findings = append(a.Findings, HardcoreFinding{Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *HardcoreAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *HardcoreAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *HardcoreAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "难度与游戏模式配置未发现风险"
	}
	sorted := make([]HardcoreFinding, len(a.Findings))
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

func shcBool(props map[string]string, key string) (bool, bool) {
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

func shcValidDifficulty(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "peaceful", "easy", "normal", "hard":
		return true
	}
	return false
}

func shcValidGamemode(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "survival", "creative", "adventure", "spectator":
		return true
	}
	return false
}

func AuditServerHardcore(serverDir string) *HardcoreAudit {
	a := &HardcoreAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(shcReasonDiff, "未配置服务器目录", false)
		return a
	}
	data, err := readBoundedFile(filepath.Join(serverDir, "server.properties"), 256*1024)
	if err != nil {
		a.add(shcReasonDiff, "无法读取 server.properties", false)
		return a
	}
	props := pxParseProperties(string(data))
	if len(props) == 0 {
		a.add(shcReasonDiff, "属性文件为空", false)
		return a
	}
	hardcore, hasHard := shcBool(props, "hardcore")
	difficulty := strings.TrimSpace(props["difficulty"])
	if difficulty != "" && !shcValidDifficulty(difficulty) {
		a.add(shcReasonDiff, "未知难度: "+cfgStripQuotes(difficulty), true)
	}
	if hasHard && hardcore {
		if difficulty != "" && shcValidDifficulty(difficulty) && strings.ToLower(difficulty) != "hard" {
			a.add(shcReasonHard, "硬核模式却设置难度 "+difficulty, true)
		}
		if pvp, hasPVP := shcBool(props, "pvp"); hasPVP && !pvp {
			a.add(shcReasonPVP, "硬核模式关闭 PVP，规则自相矛盾", false)
		}
	}
	gamemode := strings.TrimSpace(props["gamemode"])
	if gamemode != "" && !shcValidGamemode(gamemode) {
		a.add(shcReasonGamemod, "未知游戏模式: "+cfgStripQuotes(gamemode), true)
	}
	if force, hasForce := shcBool(props, "force-gamemode"); hasForce && !force {
		if strings.ToLower(strings.TrimSpace(gamemode)) == "creative" {
			a.add(shcReasonForce, "默认创造模式且不强制回写，重连可绕过限制", false)
		}
	}
	if protect, hasProtect := cfgParseInt(props["spawn-protection"]); hasProtect {
		if protect <= 0 {
			a.add(shcReasonSpawn, "出生点保护已关闭", false)
		}
	}
	return a
}
