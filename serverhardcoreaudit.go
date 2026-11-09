package main

import (
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
