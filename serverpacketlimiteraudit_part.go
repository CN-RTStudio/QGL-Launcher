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

func pklCheckAntiXray(a *PacketLimiterAudit, flat map[string]string) {
	file := "config/paper-global.yml"
	if value, ok := cfgLookup(flat, "anticheat.anti-xray.enabled"); ok {
		enabled, valid := pklBool(a, file, "anticheat.anti-xray.enabled", value)
		if valid && !enabled {
			a.add(file, pklReasonXrayOff, "anti-xray 关闭，矿脉与隐藏结构对作弊客户端可见", false)
		}
	}
	if value, ok := cfgLookup(flat, "anticheat.anti-xray.engine-mode"); ok {
		n, valid := cfgParseInt(value)
		if !valid || n < 1 || n > 3 {
			a.add(file, pklReasonXrayEngine, "anti-xray engine-mode 应为 1..3: "+value, false)
		}
	}
	for _, key := range []string{"anticheat.anti-xray.hidden-blocks", "anticheat.anti-xray.replacement-blocks"} {
		value, ok := cfgLookup(flat, key)
		if !ok {
			continue
		}
		trimmed := strings.Trim(value, "[] ")
		if trimmed == "" {
			a.add(file, pklReasonXrayEmpty, key+" 为空列表", false)
			continue
		}
		for _, item := range strings.Split(trimmed, ",") {
			block := strings.Trim(item, " '\"")
			if block == "" {
				continue
			}
			if !pklValidBlockName(block) {
				a.add(file, pklReasonBadValue, key+" 含非法方块名: "+block, false)
			}
		}
	}
}
