package main

import (
	"fmt"
	"sort"
	"strings"
)

func secCheckActivation(a *EntityCrammingAudit, flat map[string]string) {
	leaves := []string{
		"entity-activation-range.animals",
		"entity-activation-range.monsters",
		"entity-activation-range.misc",
		"entity-activation-range.water",
		"entity-activation-range.villagers",
		"entity-activation-range.flying-monsters",
	}
	for _, leaf := range leaves {
		keys := secWorldKeys(flat, leaf)
		for _, key := range keys {
			n, valid := cfgParseInt(flat[key])
			if !valid {
				a.add("spigot.yml", secReasonBadValue, key+" 不是合法整数: "+flat[key], false)
				continue
			}
			if n > secMaxActivation {
				a.add("spigot.yml", secReasonActivation, fmt.Sprintf("%s=%d 高于 %d", key, n, secMaxActivation), false)
			}
		}
	}
}

func secCheckSpawnRange(a *EntityCrammingAudit, flat map[string]string) {
	keys := secWorldKeys(flat, "mob-spawn-range")
	for _, key := range keys {
		n, valid := cfgParseInt(flat[key])
		if !valid {
			a.add("spigot.yml", secReasonBadValue, key+" 不是合法整数: "+flat[key], false)
			continue
		}
		if n > secMaxSpawnRange {
			a.add("spigot.yml", secReasonSpawnRange, fmt.Sprintf("%s=%d 高于 %d", key, n, secMaxSpawnRange), false)
		}
		if n < 1 {
			a.add("spigot.yml", secReasonBadValue, fmt.Sprintf("%s=%d 小于 1", key, n), false)
		}
	}
}

func secCheckSaveLimits(a *EntityCrammingAudit, flat map[string]string) {
	keys := make([]string, 0, 16)
	for key := range flat {
		if strings.Contains(key, "entity-per-chunk-save-limit") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		n, valid := cfgParseInt(flat[key])
		if !valid {
			a.add("spigot.yml", secReasonBadValue, key+" 不是合法整数: "+flat[key], false)
			continue
		}
		if n < 0 {
			a.add("spigot.yml", secReasonSaveLimit, key+"=-1，单区块实体保存数量不设上限", false)
		}
	}
}
