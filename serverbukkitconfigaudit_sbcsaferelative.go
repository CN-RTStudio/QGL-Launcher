package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func sbcSafeRelative(value string) (bool, string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false, "路径为空"
	}
	if filepath.IsAbs(trimmed) || strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "\\") {
		return false, "使用了绝对路径"
	}
	if strings.Contains(trimmed, "..") {
		return false, "包含越界片段"
	}
	if strings.ContainsAny(trimmed, "\\") {
		return false, "包含反斜杠"
	}
	if strings.ContainsRune(trimmed, ':') {
		return false, "包含盘符或协议分隔符"
	}
	return true, ""
}

func AuditServerBukkitConfig(serverDir string) *BukkitAudit {
	a := &BukkitAudit{ServerDir: serverDir}
	const rel = "bukkit.yml"
	if serverDir == "" {
		a.add(".", sbcReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sbcReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, sbcReasonSymlink, "配置文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, sbcMaxConfig)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, sbcReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", sbcMaxConfig), true)
			return a
		}
		a.add(rel, sbcReasonUnread, "配置文件不可读", false)
		return a
	}
	flat := cfgFlattenYAML(string(data))
	if len(flat) == 0 {
		a.add(rel, sbcReasonEmpty, "配置为空或格式不可识别", false)
		return a
	}

	if raw, found := cfgLookup(flat, "settings.connection-throttle"); found {
		value := strings.TrimSpace(raw)
		if number, parsed := cfgParseInt(value); !parsed {
			a.add(rel, sbcReasonThrottleBad, "connection-throttle 非整数", true)
		} else if number < 0 {
			a.add(rel, sbcReasonThrottle, "连接节流被关闭，刷连接不受限", true)
		} else if number == 0 {
			a.add(rel, sbcReasonThrottle, "连接节流为 0，退化为无延迟", false)
		} else if number > 10000 {
			a.add(rel, sbcReasonThrottleBad, "连接节流窗口过大", false)
		}
	}

	for _, key := range []string{"settings.permissions-file", "settings.update-folder"} {
		raw, found := cfgLookup(flat, key)
		if !found {
			continue
		}
		if ok, detail := sbcSafeRelative(raw); !ok {
			a.add(rel, sbcReasonPath, key+" "+detail, true)
		}
	}

	if raw, found := cfgLookup(flat, "settings.shutdown-message"); found && cfgHasControlChars(raw) {
		a.add(rel, sbcReasonControl, "shutdown-message 含控制字符", false)
	}

	if raw, found := cfgLookup(flat, "settings.plugin-profiling"); found {
		if strings.EqualFold(strings.TrimSpace(raw), "true") {
			a.add(rel, sbcReasonProfiling, "插件性能分析在生产环境启用", false)
		}
	}

	for _, key := range []string{"spawn-limits.monsters", "spawn-limits.animals", "spawn-limits.water-animals"} {
		raw, found := cfgLookup(flat, key)
		if !found {
			continue
		}
		if number, parsed := cfgParseInt(raw); parsed && number > 200 {
			a.add(rel, sbcReasonSpawn, key+" 上限过高", false)
		}
	}

	if raw, found := cfgLookup(flat, "chunk-gc.period-in-ticks"); found {
		if number, parsed := cfgParseInt(raw); parsed && number == 0 {
			a.add(rel, sbcReasonChunkGC, "区块回收被关闭，长时间运行内存上涨", false)
		}
	}

	return a
}
