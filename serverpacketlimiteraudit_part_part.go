package main

import "strings"

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
