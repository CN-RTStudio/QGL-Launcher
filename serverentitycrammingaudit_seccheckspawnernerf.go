package main

import (
	"fmt"
)

func secCheckSpawnerNerf(a *EntityCrammingAudit, flat map[string]string) {
	keys := secWorldKeys(flat, "nerf-spawner-mobs")
	for _, key := range keys {
		on, known := spxBool(flat[key])
		if !known {
			a.add("spigot.yml", secReasonBadValue, key+" 取值非法: "+flat[key], false)
			continue
		}
		if !on {
			a.add("spigot.yml", secReasonSpawner, key+"=false，刷怪笼实体保持完整 AI 与寻路开销", false)
		}
	}
}

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
