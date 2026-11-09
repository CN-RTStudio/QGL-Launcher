package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	secMaxFindings       = 48
	secMaxYAML           = 512 * 1024
	secDefaultCollisions = 8
	secHardCollisions    = 32
	secMaxActivation     = 48
	secMaxSpawnRange     = 10
	secReasonOK          = "ok"
	secReasonMissing     = "missing"
	secReasonSymlink     = "symlink"
	secReasonTooLarge    = "too-large"
	secReasonUnread      = "unreadable"
	secReasonBadValue    = "bad-value"
	secReasonCramming    = "entity-cramming-disabled"
	secReasonSpawner     = "spawner-nerf-disabled"
	secReasonActivation  = "entity-activation-range-large"
	secReasonSpawnRange  = "mob-spawn-range-large"
	secReasonSaveLimit   = "entity-save-limit-unbounded"
	secReasonPaperLimit  = "paper-entity-save-limit-unbounded"
)

type EntityCrammingFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type EntityCrammingAudit struct {
	ServerDir string
	Findings  []EntityCrammingFinding
}

func (a *EntityCrammingAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= secMaxFindings {
		return
	}
	a.Findings = append(a.Findings, EntityCrammingFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *EntityCrammingAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f EntityCrammingFinding) bool { return f.Blocking })
}

func (a *EntityCrammingAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if f.Reason != secReasonOK && !f.Blocking {
			return true
		}
	}
	return false
}

func (a *EntityCrammingAudit) Describe() string {
	return describeFindings(a.Findings, func(f EntityCrammingFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func secLoadText(a *EntityCrammingAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

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
