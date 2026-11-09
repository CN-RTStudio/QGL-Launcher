package main

import (
	"fmt"
	"os"
	"path/filepath"
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

func secCheckPaperChunkLimits(a *EntityCrammingAudit, flat map[string]string) {
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
			a.add("config/paper-global.yml", secReasonBadValue, key+" 不是合法整数: "+flat[key], false)
			continue
		}
		if n < 0 {
			a.add("config/paper-global.yml", secReasonPaperLimit, key+"=-1，Paper 单区块实体保存不设上限", false)
		}
	}
}

func AuditServerEntityCramming(serverDir string) *EntityCrammingAudit {
	a := &EntityCrammingAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", secReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", secReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", secReasonMissing, "服务器目录不存在", false)
		return a
	}

	if text, ok := secLoadText(a, serverDir, "spigot.yml", secMaxYAML); ok {
		flat := cfgFlattenYAML(text)
		secCheckCollisions(a, flat)
		secCheckSpawnerNerf(a, flat)
		secCheckActivation(a, flat)
		secCheckSpawnRange(a, flat)
		secCheckSaveLimits(a, flat)
	}

	if text, ok := secLoadText(a, serverDir, filepath.Join("config", "paper-global.yml"), secMaxYAML); ok {
		secCheckPaperChunkLimits(a, cfgFlattenYAML(text))
	}

	if len(a.Findings) == 0 {
		a.add("spigot.yml", secReasonOK, "未发现实体堆积相关配置", false)
	}
	return a
}
