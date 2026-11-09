package main

import (
	"fmt"
	"strconv"
	"strings"
)

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
