package main

import (
	"fmt"
)

const (
	cfdMaxFindings      = 48
	cfdMaxProps         = 256 * 1024
	cfdMaxYAML          = 512 * 1024
	cfdThrottleMin      = 1
	cfdThrottleMax      = 10000
	cfdTimeoutMax       = 600
	cfdJoinBurstMax     = 10
	cfdMaxPlayersMax    = 200
	cfdReasonOK         = "ok"
	cfdReasonMissing    = "missing"
	cfdReasonSymlink    = "symlink"
	cfdReasonTooLarge   = "too-large"
	cfdReasonUnreadable = "unreadable"
	cfdReasonBadConfig  = "bad-config"
	cfdReasonBadValue   = "bad-value"
	cfdThrottleOff      = "throttle-disabled"
	cfdThrottleLoose    = "throttle-loose"
	cfdTimeoutLoose     = "slow-timeout"
	cfdJoinBurst        = "join-burst"
	cfdPlayersBulk      = "max-players-large"
	cfdRateLimitOff     = "rate-limit-disabled"
	cfdConflict         = "duplicate-setting"
)

type ConnectionFloodFinding = auditFinding

type ConnectionFloodAudit struct {
	ServerDir string
	Findings  []ConnectionFloodFinding
}

func (a *ConnectionFloodAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, cfdMaxFindings, ConnectionFloodFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *ConnectionFloodAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ConnectionFloodFinding) bool { return f.Blocking })
}

func (a *ConnectionFloodAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f ConnectionFloodFinding) bool { return f.Reason != cfdReasonOK && !f.Blocking })
}

func (a *ConnectionFloodAudit) Describe() string {
	return describeFindings(a.Findings, func(f ConnectionFloodFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func cfdLoad(a *ConnectionFloodAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func cfdIntField(a *ConnectionFloodAudit, file, label, value string) (int, bool) {
	n, ok := cfgParseInt(value)
	if !ok {
		a.add(file, cfdReasonBadValue, label+" 不是合法整数: "+value, false)
		return 0, false
	}
	return n, true
}

func cfdCheckThrottle(a *ConnectionFloodAudit, file string, flat map[string]string) {
	value, ok := cfgLookup(flat, "settings.connection-throttle")
	if !ok {
		return
	}
	n, valid := cfdIntField(a, file, "connection-throttle", value)
	if !valid {
		return
	}
	if n < cfdThrottleMin {
		a.add(file, cfdThrottleOff, fmt.Sprintf("connection-throttle=%d 关闭了重连节流，可被快速重连放大", n), true)
		return
	}
	if n > cfdThrottleMax {
		a.add(file, cfdThrottleLoose, fmt.Sprintf("connection-throttle=%d 超过 %d 毫秒", n, cfdThrottleMax), false)
	}
}

func cfdCheckSpigot(a *ConnectionFloodAudit, flat map[string]string) {
	if value, ok := cfgLookup(flat, "settings.timeout-time"); ok {
		n, valid := cfdIntField(a, "spigot.yml", "settings.timeout-time", value)
		if valid {
			if n <= 0 {
				a.add("spigot.yml", cfdReasonBadValue, fmt.Sprintf("settings.timeout-time=%d 不是正数", n), false)
			} else if n > cfdTimeoutMax {
				a.add("spigot.yml", cfdTimeoutLoose, fmt.Sprintf("settings.timeout-time=%d 超过 %d 秒，慢连接占用时间过长", n, cfdTimeoutMax), false)
			}
		}
	}
	if value, ok := cfgLookup(flat, "settings.player-shuffle"); ok {
		n, valid := cfdIntField(a, "spigot.yml", "settings.player-shuffle", value)
		if valid && n < 0 {
			a.add("spigot.yml", cfdReasonBadValue, fmt.Sprintf("settings.player-shuffle=%d 为负数", n), false)
		}
	}
	if value, ok := cfgLookup(flat, "settings.connection-throttle"); ok {
		n, valid := cfdIntField(a, "spigot.yml", "settings.connection-throttle", value)
		if valid && n < cfdThrottleMin {
			a.add("spigot.yml", cfdThrottleOff, fmt.Sprintf("settings.connection-throttle=%d 关闭了重连节流", n), true)
		}
	}
}
