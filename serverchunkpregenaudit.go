package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	spgMaxFindings      = 36
	spgMaxConfig        = 256 * 1024
	spgMaxRadius        = 8192
	spgWarnRadius       = 4096
	spgReasonOK         = "ok"
	spgReasonMissing    = "missing"
	spgReasonSymlink    = "symlink"
	spgReasonTooLarge   = "too-large"
	spgReasonUnreadable = "unreadable"
	spgReasonNoConfig   = "config-missing"
	spgReasonRadius     = "radius-invalid"
	spgReasonRadiusBig  = "radius-too-large"
	spgReasonWorld      = "world-name-invalid"
	spgReasonTasksPath  = "task-world-path"
	spgReasonBadValue   = "bad-value"
	spgReasonSilent     = "silent-progress-disabled"
)

type PregenFinding = auditFinding

type PregenAudit struct {
	ServerDir string
	Findings  []PregenFinding
}

func (a *PregenAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spgMaxFindings, PregenFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PregenAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PregenFinding) bool { return f.Blocking })
}

func (a *PregenAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PregenAudit) Describe() string {
	return describeFileReason("区块预生成配置未发现风险", a.Findings, 12)
}

func spgLoadText(a *PregenAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func spgText(flat map[string]string, path string) (string, bool) {
	value, ok := cfgLookup(flat, path)
	if !ok {
		return "", false
	}
	return cfgStripQuotes(value), true
}

func spgWorldProblem(name string) bool {
	if name == "" {
		return true
	}
	if cfgHasControlChars(name) {
		return true
	}
	if strings.ContainsAny(name, "/\\:") || strings.Contains(name, "..") {
		return true
	}
	return false
}

func spgListItems(text, key string) []string {
	lines := strings.Split(text, "\n")
	items := []string{}
	baseIndent := -1
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if baseIndent < 0 {
			colon := strings.Index(trimmed, ":")
			if colon < 0 {
				continue
			}
			if strings.TrimSpace(trimmed[:colon]) != key {
				continue
			}
			if strings.TrimSpace(trimmed[colon+1:]) != "" {
				continue
			}
			baseIndent = saxIndent(line)
			continue
		}
		if saxIndent(line) <= baseIndent {
			break
		}
		if !strings.HasPrefix(trimmed, "- ") {
			break
		}
		items = append(items, cfgStripQuotes(strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))))
		if len(items) > 128 {
			break
		}
	}
	return items
}

func AuditServerPregen(serverDir string) *PregenAudit {
	a := &PregenAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", spgReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", spgReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", spgReasonMissing, "服务器目录不存在", false)
		return a
	}

	text, ok := spgLoadText(a, serverDir, "plugins/Chunky/config.yml", spgMaxConfig)
	if !ok {
		return a
	}
	flat := cfgFlattenYAML(text)

	radiusText, hasRadius := spgText(flat, "radius")
	if !hasRadius {
		a.add("plugins/Chunky/config.yml", spgReasonNoConfig, "未声明 radius", false)
	} else if radius, parsed := cfgParseInt(radiusText); !parsed || radius <= 0 {
		a.add("plugins/Chunky/config.yml", spgReasonRadius, "radius 非法", true)
	} else if radius > spgMaxRadius {
		a.add("plugins/Chunky/config.yml", spgReasonRadius, fmt.Sprintf("radius=%d 超出上限 %d", radius, spgMaxRadius), true)
	} else if radius > spgWarnRadius {
		a.add("plugins/Chunky/config.yml", spgReasonRadiusBig, fmt.Sprintf("radius=%d 预生成范围过大", radius), false)
	}

	if world, found := spgText(flat, "world"); found && spgWorldProblem(world) {
		a.add("plugins/Chunky/config.yml", spgReasonWorld, "world 名称含非法字符", true)
	}

	for _, world := range spgListItems(text, "worlds") {
		if spgWorldProblem(world) {
			a.add("plugins/Chunky/config.yml", spgReasonWorld, "worlds 列表含非法世界名", true)
			break
		}
	}

	if silent, found := cfgLookup(flat, "silent"); found {
		if strings.EqualFold(cfgStripQuotes(silent), "false") {
			a.add("plugins/Chunky/config.yml", spgReasonSilent, "silent=false 会持续输出进度", false)
		}
	}

	for _, key := range []string{"sleep", "save-interval"} {
		value, found := spgText(flat, key)
		if !found {
			continue
		}
		if number, parsed := cfgParseInt(value); !parsed || number < 0 {
			a.add("plugins/Chunky/config.yml", spgReasonBadValue, key+" 非法", true)
		}
	}

	if text, ok := spgLoadText(a, serverDir, "plugins/Chunky/tasks.yml", spgMaxConfig); ok {
		for _, world := range spgListItems(text, "worlds") {
			if spgWorldProblem(world) {
				a.add("plugins/Chunky/tasks.yml", spgReasonTasksPath, "任务世界名含路径片段", true)
				break
			}
		}
	}
	return a
}
