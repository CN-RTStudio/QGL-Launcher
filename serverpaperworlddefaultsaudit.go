package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	swdMaxFindings = 32
	swdMaxFile     = 256 * 1024
	swdReasonMiss  = "missing"
	swdReasonLink  = "symlink"
	swdReasonLarge = "too-large"
	swdReasonRead  = "unreadable"
	swdReasonEmpty = "empty-config"
	swdReasonXray  = "anti-xray-disabled"
	swdReasonColl  = "collision-limit"
	swdReasonRate  = "tick-rate-zero"
	swdReasonSave  = "autosave-zero"
	swdReasonRange = "despawn-range-invalid"
	swdReasonScan  = "hopper-scan-high"
	swdReasonChunk = "chunk-unload-disabled"
	swdReasonAlt   = "height-limit-high"
)

type PaperWorldFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type PaperWorldAudit struct {
	ServerDir string
	Findings  []PaperWorldFinding
}

func (a *PaperWorldAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= swdMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PaperWorldFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PaperWorldAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *PaperWorldAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *PaperWorldAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "paper-world-defaults.yml 未发现风险"
	}
	sorted := make([]PaperWorldFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Detail < sorted[j].Detail
	})
	var b strings.Builder
	for i, f := range sorted {
		if i >= 12 {
			b.WriteString(fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		if i > 0 {
			b.WriteString("；")
		}
		b.WriteString(f.Reason)
		if f.Detail != "" {
			b.WriteString("(")
			b.WriteString(f.Detail)
			b.WriteString(")")
		}
	}
	return b.String()
}

func AuditServerPaperWorldDefaults(serverDir string) *PaperWorldAudit {
	a := &PaperWorldAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("config/paper-world-defaults.yml", swdReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "config/paper-world-defaults.yml"
	path := filepath.Join(serverDir, filepath.FromSlash(rel))
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, swdReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, swdReasonLink, "世界默认配置是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, swdReasonMiss, "未找到 paper-world-defaults.yml", false)
		return a
	}
	data, err := readBoundedFile(path, swdMaxFile)
	if err != nil {
		reason := swdReasonRead
		if err == errLocalFileTooLarge {
			reason = swdReasonLarge
		}
		a.add(rel, reason, err.Error(), true)
		return a
	}
	text := string(data)
	if strings.TrimSpace(text) == "" {
		a.add(rel, swdReasonEmpty, "配置文件为空", false)
		return a
	}
	flat := cfgFlattenYAML(text)
	if len(flat) == 0 {
		a.add(rel, swdReasonEmpty, "配置无法解析", false)
		return a
	}

	if raw, ok := cfgLookup(flat, "anticheat.anti-xray.enabled"); ok {
		if strings.EqualFold(cfgStripQuotes(raw), "false") {
			a.add(rel, swdReasonXray, "反透视已关闭", false)
		}
	}
	if v, ok := cfgLookup(flat, "collisions.max-entity-collisions"); ok {
		if n, ok2 := cfgParseInt(v); ok2 && n > 8 {
			a.add(rel, swdReasonColl, fmt.Sprintf("实体挤压上限 %d", n), false)
		}
	}
	zeroTick := []string{
		"tick-rates.mob-spawner",
		"tick-rates.grass-smnead",
		"tick-rates.random-tick-setbed",
	}
	for _, key := range zeroTick {
		if v, ok := cfgLookup(flat, key); ok {
			if n, ok2 := cfgParseInt(v); ok2 && n <= 0 {
				a.add(rel, swdReasonRate, key+" 被关闭", false)
			}
		}
	}
	if v, ok := cfgLookup(flat, "chunks.max-auto-save-chunks-per-tick"); ok {
		if n, ok2 := cfgParseInt(v); ok2 && n <= 0 {
			a.add(rel, swdReasonSave, "自动保存区块数为 0", true)
		}
	}
	if v, ok := cfgLookup(flat, "chunks.prevent-moving-into-unloaded-chunks"); ok {
		if strings.EqualFold(cfgStripQuotes(v), "false") {
			a.add(rel, swdReasonChunk, "允许进入未加载区块", false)
		}
	}
	for key, value := range flat {
		if strings.Contains(key, "despawn-ranges.") {
			if n, ok := cfgParseInt(value); ok && (n <= 0 || n > 128) {
				a.add(rel, swdReasonRange, key+"="+value, false)
			}
		}
		if strings.Contains(key, "hopper.") && strings.HasSuffix(key, "cooldown-when-full") {
			continue
		}
	}
	if v, ok := cfgLookup(flat, "environment.max-entity-collisions"); ok {
		if n, ok2 := cfgParseInt(v); ok2 && n < 0 {
			a.add(rel, swdReasonColl, "实体碰撞上限为负", false)
		}
	}
	if v, ok := cfgLookup(flat, "worldgen.max-height"); ok {
		if n, ok2 := cfgParseInt(v); ok2 && n > 512 {
			a.add(rel, swdReasonAlt, "世界高度上限过高", false)
		}
	}
	return a
}
