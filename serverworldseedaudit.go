package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	swsMaxFindings     = 32
	swsMaxProps        = 256 * 1024
	swsMaxPlayers      = 500
	swsMaxViewDistance = 16
	swsReasonMissing   = "missing"
	swsReasonSymlink   = "symlink"
	swsReasonTooLarge  = "too-large"
	swsReasonUnread    = "unreadable"
	swsReasonSeed      = "world-seed-exposed"
	swsReasonSeedBad   = "world-seed-invalid"
	swsReasonPlayers   = "max-players-invalid"
	swsReasonView      = "view-distance-too-large"
	swsReasonSim       = "simulation-distance-too-large"
)

type WorldSeedFinding = auditFinding

type WorldSeedAudit struct {
	ServerDir string
	Findings  []WorldSeedFinding
}

func (a *WorldSeedAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, swsMaxFindings, WorldSeedFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WorldSeedAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WorldSeedFinding) bool { return f.Blocking })
}

func (a *WorldSeedAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WorldSeedAudit) Describe() string {
	return describeFileReasonDetail("世界种子与容量配置未发现风险", a.Findings, 12)
}

func AuditServerWorldSeed(serverDir string) *WorldSeedAudit {
	a := &WorldSeedAudit{ServerDir: serverDir}
	const rel = "server.properties"
	if serverDir == "" {
		a.add(".", swsReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", swsReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, swsReasonSymlink, "属性文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, swsMaxProps)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, swsReasonTooLarge, fmt.Sprintf("属性文件超过 %d 字节", swsMaxProps), true)
			return a
		}
		a.add(rel, swsReasonUnread, "属性文件不可读", false)
		return a
	}
	props := pxParseProperties(string(data))
	if len(props) == 0 {
		a.add(rel, swsReasonMissing, "属性文件为空或格式不可识别", false)
		return a
	}

	if raw, found := props["level-seed"]; found {
		trimmed := strings.TrimSpace(raw)
		if cfgHasControlChars(trimmed) {
			a.add(rel, swsReasonSeedBad, "level-seed 含控制字符", true)
		} else if trimmed != "" && trimmed != "0" {
			if _, err := strconv.ParseInt(trimmed, 10, 64); err == nil || len(trimmed) > 0 {
				a.add(rel, swsReasonSeed, "世界种子固定写入配置，结构可被预测", false)
			}
		}
	}

	if raw, found := props["max-players"]; found {
		trimmed := strings.TrimSpace(raw)
		if value, parsed := cfgParseInt(trimmed); !parsed || value <= 0 || value > swsMaxPlayers {
			a.add(rel, swsReasonPlayers, "max-players 非法或超出合理上限", false)
		}
	}

	if raw, found := props["view-distance"]; found {
		if value, parsed := cfgParseInt(strings.TrimSpace(raw)); parsed && value > swsMaxViewDistance {
			a.add(rel, swsReasonView, fmt.Sprintf("view-distance=%d 超过 %d", value, swsMaxViewDistance), false)
		}
	}
	if raw, found := props["simulation-distance"]; found {
		if value, parsed := cfgParseInt(strings.TrimSpace(raw)); parsed && value > swsMaxViewDistance {
			a.add(rel, swsReasonSim, fmt.Sprintf("simulation-distance=%d 超过 %d", value, swsMaxViewDistance), false)
		}
	}

	return a
}
