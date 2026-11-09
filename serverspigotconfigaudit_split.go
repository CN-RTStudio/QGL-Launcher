package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func AuditServerSpigotConfig(serverDir string) *SpigotAudit {
	a := &SpigotAudit{ServerDir: serverDir}
	const rel = "spigot.yml"
	if serverDir == "" {
		a.add(".", sptReasonMiss, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sptReasonLink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, sptReasonLink, "Spigot 配置为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, sptMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, sptReasonLarge, fmt.Sprintf("Spigot 配置超过 %d 字节", sptMaxFile), true)
			return a
		}
		a.add(rel, sptReasonRead, "Spigot 配置不可读", false)
		return a
	}
	cfg := cfgFlattenYAML(string(data))
	if len(cfg) == 0 {
		a.add(rel, sptReasonEmpty, "Spigot 配置为空或格式不可识别", false)
		return a
	}

	if value, found := cfgLookup(cfg, "settings.bungeecord"); found && pacParseBool(value) {
		a.add(rel, sptReasonBungee, "开启 BungeeCord 模式会信任上游伪造的玩家 UUID", true)
	}
	if value, found := cfgLookup(cfg, "settings.restart-script"); found {
		script := cfgStripQuotes(value)
		if script != "" && script != "restart.sh" {
			a.add(rel, sptReasonScript, "重启脚本指向 "+script, true)
		} else if script != "" {
			a.add(rel, sptReasonScript, "重启脚本由服务端直接执行", false)
		}
	}
	if value, found := cfgLookup(cfg, "messages.whitelist"); found {
		message := cfgStripQuotes(value)
		if sptHasControlChars(message) {
			a.add(rel, sptReasonMsg, "白名单提示语含控制字符", true)
		}
	}
	if value, found := cfgLookup(cfg, "settings.timeout-time"); found {
		if seconds, parsed := cfgParseInt(cfgStripQuotes(value)); parsed && seconds > 180 {
			a.add(rel, sptReasonTimeout, fmt.Sprintf("连接超时 %d 秒过长", seconds), false)
		}
	}
	if value, found := cfgLookup(cfg, "world-settings.default.max-tnt-per-tick"); found {
		if count, parsed := cfgParseInt(cfgStripQuotes(value)); parsed && count > 200 {
			a.add(rel, sptReasonTNT, fmt.Sprintf("max-tnt-per-tick=%d 超过 200", count), false)
		}
	}
	for _, entity := range []string{"monsters", "animals", "misc", "water"} {
		if value, found := cfgLookup(cfg, "world-settings.default.entity-activation-range."+entity); found {
			if blocks, parsed := cfgParseInt(cfgStripQuotes(value)); parsed && blocks > 64 {
				a.add(rel, sptReasonRange, fmt.Sprintf("%s 激活范围 %d 超过 64", entity, blocks), false)
			}
		}
	}
	for _, key := range []string{"world-settings.default.ticks-per.hopper-transfer", "world-settings.default.ticks-per.hopper-check"} {
		if value, found := cfgLookup(cfg, key); found {
			if ticks, parsed := cfgParseInt(cfgStripQuotes(value)); parsed && ticks <= 0 {
				a.add(rel, sptReasonRate, key+" 被设置为 0，逻辑将每刻执行", false)
			}
		}
	}
	if value, found := cfgLookup(cfg, "world-settings.default.merge-radius.item"); found {
		if radius, parsed := sptParseFloat(cfgStripQuotes(value)); parsed && radius < 0 {
			a.add(rel, sptReasonMerge, fmt.Sprintf("物品合并半径 %v 为负值", radius), false)
		}
	}
	if value, found := cfgLookup(cfg, "world-settings.default.disable-saving"); found && pacParseBool(value) {
		a.add(rel, sptReasonSaving, "世界保存被关闭，数据可能丢失", false)
	}
	return a
}

func sptParseFloat(value string) (float64, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, false
	}
	number, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0, false
	}
	return number, true
}
