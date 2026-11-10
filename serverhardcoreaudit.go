package main

import (
	"path/filepath"
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
	a.Findings = appendAuditFinding(a.Findings, shcMaxFindings, HardcoreFinding{Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *HardcoreAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f HardcoreFinding) bool { return f.Blocking })
}

func (a *HardcoreAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *HardcoreAudit) Describe() string {
	return describeAuditFindings("难度与游戏模式配置未发现风险", a.Findings, 10,
		func(f HardcoreFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f HardcoreFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func shcBool(props map[string]string, key string) (bool, bool) {
	return propsBoolValue(props, key)
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
