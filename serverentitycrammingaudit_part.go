package main

import (
	"fmt"
	"sort"
	"strings"
)

func secWorldKeys(flat map[string]string, leaf string) []string {
	out := make([]string, 0, 16)
	for key := range flat {
		if !strings.HasSuffix(key, "."+leaf) {
			continue
		}
		if !strings.HasPrefix(key, "world-settings.") {
			continue
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func secCheckCollisions(a *EntityCrammingAudit, flat map[string]string) {
	keys := secWorldKeys(flat, "max-entity-collisions")
	for _, key := range keys {
		value := flat[key]
		n, valid := cfgParseInt(value)
		switch {
		case !valid:
			a.add("spigot.yml", secReasonBadValue, key+" 不是合法整数: "+value, false)
		case n == 0:
			a.add("spigot.yml", secReasonCramming, key+"=0，实体挤压伤害被关闭，实体可无限堆叠", true)
		case n > secHardCollisions:
			a.add("spigot.yml", secReasonCramming, fmt.Sprintf("%s=%d 高于 %d", key, n, secHardCollisions), false)
		case n > secDefaultCollisions:
			a.add("spigot.yml", secReasonCramming, fmt.Sprintf("%s=%d 高于默认 %d", key, n, secDefaultCollisions), false)
		}
	}
}

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
