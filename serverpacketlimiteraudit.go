package main

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	pklMaxFindings        = 48
	pklMaxYAML            = 512 * 1024
	pklMaxRate            = 600
	pklMaxAutoSave        = 24
	pklMaxKickMessage     = 256
	pklReasonOK           = "ok"
	pklReasonMissing      = "missing"
	pklReasonSymlink      = "symlink"
	pklReasonTooLarge     = "too-large"
	pklReasonUnreadable   = "unreadable"
	pklReasonBadConfig    = "bad-config"
	pklReasonBadValue     = "bad-value"
	pklReasonLimiterOff   = "limiter-disabled"
	pklReasonLimiterLoose = "limiter-loose"
	pklReasonKickMessage  = "bad-kick-message"
	pklReasonXrayOff      = "anti-xray-disabled"
	pklReasonXrayEngine   = "bad-engine-mode"
	pklReasonXrayEmpty    = "empty-block-list"
	pklReasonAutoSave     = "auto-save-burst"
)

type PacketLimiterFinding = auditFinding

type PacketLimiterAudit struct {
	ServerDir string
	Limits    int
	Findings  []PacketLimiterFinding
}

func (a *PacketLimiterAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pklMaxFindings, PacketLimiterFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PacketLimiterAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PacketLimiterFinding) bool { return f.Blocking })
}

func (a *PacketLimiterAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PacketLimiterFinding) bool { return f.Reason != pklReasonOK && !f.Blocking })
}

func pklCheckLimiter(a *PacketLimiterAudit, flat map[string]string) {
	file := "config/paper-global.yml"
	if value, ok := cfgLookup(flat, "packet-limiter.enabled"); ok {
		enabled, valid := pklBool(a, file, "packet-limiter.enabled", value)
		if valid && !enabled {
			a.add(file, pklReasonLimiterOff, "packet-limiter.enabled=false，入站包速率不受限", true)
		}
	}

	rateKeys := []string{"packet-limiter.all-packets.max-packet-rate", "packet-limiter.all-packets.max-packet-rate-kick"}
	for _, key := range rateKeys {
		value, ok := cfgLookup(flat, key)
		if !ok {
			continue
		}
		n, valid := cfgParseInt(value)
		if !valid {
			a.add(file, pklReasonBadValue, key+" 不是合法整数: "+value, false)
			continue
		}
		if n <= 0 {
			a.add(file, pklReasonBadValue, fmt.Sprintf("%s=%d 不是正数", key, n), false)
			continue
		}
		if n > pklMaxRate {
			a.add(file, pklReasonLimiterLoose, fmt.Sprintf("%s=%d 超过 %d", key, n, pklMaxRate), false)
		}
		a.Limits++
	}

	if value, ok := cfgLookup(flat, "packet-limiter.all-packets.interval"); ok {
		n, ferr := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if ferr != nil || n <= 0 {
			a.add(file, pklReasonBadValue, "packet-limiter 采样间隔非法: "+value, false)
		}
	}

	if value, ok := cfgLookup(flat, "packet-limiter.kick-message"); ok {
		if cfgHasControlChars(value) {
			a.add(file, pklReasonKickMessage, "踢出消息包含控制字符", false)
		}
		if len([]rune(value)) > pklMaxKickMessage {
			a.add(file, pklReasonKickMessage, fmt.Sprintf("踢出消息长度 %d 超过 %d", len([]rune(value)), pklMaxKickMessage), false)
		}
	}
}
