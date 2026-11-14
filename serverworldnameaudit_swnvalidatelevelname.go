package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func swnValidateLevelName(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "level-name 为空"
	}
	if filepath.IsAbs(trimmed) || strings.HasPrefix(trimmed, "/") {
		return "level-name 使用绝对路径"
	}
	if strings.Contains(trimmed, "..") {
		return "level-name 包含越界片段"
	}
	if strings.ContainsAny(trimmed, "\\:") {
		return "level-name 包含反斜杠或盘符"
	}
	if cfgHasControlChars(trimmed) {
		return "level-name 含控制字符"
	}
	return ""
}

func AuditServerWorldName(serverDir string) *WorldNameAudit {
	a := &WorldNameAudit{ServerDir: serverDir}
	const rel = "server.properties"
	if serverDir == "" {
		a.add(".", swnReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", swnReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, swnReasonSymlink, "属性文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, swnMaxProps)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			a.add(rel, swnReasonNoProps, "未找到服务器属性文件", false)
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, swnReasonTooLarge, fmt.Sprintf("属性文件超过 %d 字节", swnMaxProps), true)
			return a
		}
		a.add(rel, swnReasonUnread, "属性文件不可读", false)
		return a
	}
	props := pxParseProperties(string(data))
	if len(props) == 0 {
		a.add(rel, swnReasonNoProps, "属性文件为空或格式不可识别", false)
		return a
	}

	levelName := "world"
	if raw, found := props["level-name"]; found {
		if detail := swnValidateLevelName(raw); detail != "" {
			a.add(rel, swnReasonName, detail, true)
		} else {
			levelName = strings.TrimSpace(raw)
		}
	}

	if levelName != "" && !strings.Contains(levelName, "..") {
		candidate := filepath.Join(serverDir, filepath.FromSlash(levelName))
		if info, err := os.Lstat(candidate); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				a.add(levelName, swnReasonDirLink, "世界目录为符号链接，数据可落在服务器目录之外", true)
			}
		}
	}

	if raw, found := props["level-type"]; found {
		normalized := strings.ToLower(strings.TrimSpace(raw))
		if normalized != "" && !swnKnownLevelTypes[normalized] && !strings.HasPrefix(normalized, "minecraft:") {
			a.add(rel, swnReasonLevelType, "level-type 使用了未知生成器", false)
		}
	}

	if raw, found := props["generator-settings"]; found {
		trimmed := strings.TrimSpace(raw)
		if trimmed != "" && trimmed != "{}" {
			a.add(rel, swnReasonGenerator, "generator-settings 含自定义生成参数", false)
		}
	}

	return a
}
