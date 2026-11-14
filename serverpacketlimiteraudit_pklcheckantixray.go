package main

import (
	"fmt"
	"strings"
)

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

func pklValidBlockName(name string) bool {
	if name == "" || len(name) > 96 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == ':' || c == '.' || c == '-' || c == '#'
		if !ok {
			return false
		}
	}
	return true
}
func pklCheckChunkLoading(a *PacketLimiterAudit, flat map[string]string) {
	file := "config/paper-global.yml"
	if value, ok := cfgLookup(flat, "chunk-loading.max-auto-save-chunks-per-tick"); ok {
		n, valid := cfgParseInt(value)
		if !valid || n <= 0 {
			a.add(file, pklReasonBadValue, "max-auto-save-chunks-per-tick 非法: "+value, false)
			return
		}
		if n > pklMaxAutoSave {
			a.add(file, pklReasonAutoSave, fmt.Sprintf("max-auto-save-chunks-per-tick=%d 超过 %d", n, pklMaxAutoSave), false)
		}
	}
	if value, ok := cfgLookup(flat, "chunk-loading.prevent-moving-into-unloaded-chunks"); ok {
		prevent, valid := pklBool(a, file, "prevent-moving-into-unloaded-chunks", value)
		if valid && !prevent {
			a.add(file, pklReasonAutoSave, "允许玩家进入未加载区块，可被用于拉爆区块加载", false)
		}
	}
}

func pklCheckOverrides(a *PacketLimiterAudit, flat map[string]string) {
	file := "config/paper-global.yml"
	count := 0
	for key, value := range flat {
		if !strings.HasPrefix(key, "packet-limiter.overrides.") {
			continue
		}
		if !strings.HasSuffix(key, ".max-packet-rate") {
			continue
		}
		count++
		n, valid := cfgParseInt(value)
		if !valid || n <= 0 {
			a.add(file, pklReasonBadValue, key+" 非法: "+value, false)
			continue
		}
		if n > pklMaxRate {
			a.add(file, pklReasonLimiterLoose, fmt.Sprintf("%s=%d 超过 %d", key, n, pklMaxRate), false)
		}
	}
	if count > 64 {
		a.add(file, pklReasonLimiterLoose, fmt.Sprintf("overrides 条目 %d 过多", count), false)
	}
}
