package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func pcLookupKey(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return "", "", false
	}
	cut := strings.IndexAny(trimmed, ":=")
	if cut <= 0 {
		return "", "", false
	}
	key := strings.ToLower(strings.TrimSpace(trimmed[:cut]))
	value := strings.TrimSpace(trimmed[cut+1:])
	key = strings.Trim(key, `"'`)
	return key, value, true
}

func pcBoolValue(value string) (bool, bool) {
	cleaned := strings.Trim(strings.TrimSpace(value), `"'`)
	cleaned = strings.TrimRight(cleaned, ",")
	switch strings.ToLower(cleaned) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	}
	return false, false
}

func pcValueEmpty(value string) bool {
	cleaned := strings.Trim(strings.TrimSpace(value), `"'`)
	cleaned = strings.TrimRight(cleaned, ",")
	return cleaned == "" || cleaned == "''" || cleaned == `""` || cleaned == "null"
}

func pcScanLines(audit *PluginConfigAudit, name string, data []byte) {
	lines := strings.Split(string(data), "\n")
	if len(lines) > pcMaxLineScan {
		lines = lines[:pcMaxLineScan]
	}
	for _, line := range lines {
		key, value, ok := pcLookupKey(line)
		if !ok {
			continue
		}
		plainKey := key
		if idx := strings.LastIndex(plainKey, "."); idx >= 0 {
			plainKey = plainKey[idx+1:]
		}
		for _, danger := range pcDangerousKeys {
			if plainKey != danger {
				continue
			}
			if enabled, ok := pcBoolValue(value); ok && enabled {
				audit.add(name, pcReasonDangerousToggle, "启用了危险开关 "+plainKey, true)
			}
			break
		}
		for _, secret := range pcSecretKeys {
			if plainKey != secret {
				continue
			}
			if !pcValueEmpty(value) && !strings.HasPrefix(strings.TrimSpace(value), "${") {
				audit.add(name, pcReasonPlaintextSecret, "明文凭据字段 "+plainKey, false)
			}
			break
		}
	}
}

func pcReadBounded(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	limited := io.LimitReader(f, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("超过体积上限 %d", maxBytes)
	}
	return data, nil
}

func pcInspectFile(audit *PluginConfigAudit, rel, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		audit.add(rel, pcReasonUnreadable, "无法读取插件配置", true)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(rel, pcReasonSymlink, "插件配置是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(rel, pcReasonUnreadable, "插件配置不是普通文件", true)
		return
	}
	if info.Size() > pcMaxFileBytes {
		audit.add(rel, pcReasonTooLarge, "插件配置超过体积预算", true)
		return
	}
	if info.Mode().Perm()&0o022 != 0 {
		audit.add(rel, pcReasonWorldReadable, "插件配置对其他用户可写", false)
	}
	data, err := pcReadBounded(path, pcMaxFileBytes)
	if err != nil {
		audit.add(rel, pcReasonUnreadable, "插件配置读取失败", false)
		return
	}
	pcScanLines(audit, rel, data)
}

func AuditServerPluginConfig(serverDir string) PluginConfigAudit {
	audit := PluginConfigAudit{Dir: serverDir}
	root := filepath.Join(serverDir, "plugins")
	entries, err := os.ReadDir(root)
	if err != nil {
		audit.add("plugins", pcReasonMissing, "未发现 plugins 目录", false)
		audit.add("", pcReasonOK, "无插件配置", false)
		return audit
	}
	for _, plugin := range entries {
		if len(audit.Files) >= pcMaxFiles {
			audit.add("plugins", pcReasonTooMany, "插件目录数量超过预算", true)
			break
		}
		base := filepath.Join(root, plugin.Name())
		if plugin.IsDir() {
			names, err := os.ReadDir(base)
			if err != nil {
				audit.add(filepath.Join("plugins", plugin.Name()), pcReasonUnreadable, "插件目录不可读", true)
				continue
			}
			for _, name := range names {
				if name.IsDir() {
					audit.add(filepath.Join("plugins", plugin.Name(), name.Name()), pcReasonDepthExceeded, "插件配置目录层级超出预算", false)
					continue
				}
				lower := strings.ToLower(name.Name())
				match := false
				for _, ext := range pcConfigExts {
					if strings.HasSuffix(lower, ext) {
						match = true
						break
					}
				}
				if !match {
					continue
				}
				rel := filepath.Join("plugins", plugin.Name(), name.Name())
				audit.Files = append(audit.Files, rel)
				pcInspectFile(&audit, rel, filepath.Join(base, name.Name()))
			}
			continue
		}
		lower := strings.ToLower(plugin.Name())
		for _, ext := range pcConfigExts {
			if !strings.HasSuffix(lower, ext) {
				continue
			}
			rel := filepath.Join("plugins", plugin.Name())
			audit.Files = append(audit.Files, rel)
			pcInspectFile(&audit, rel, base)
			break
		}
	}
	if len(audit.Findings) == 0 {
		audit.add("", pcReasonOK, "插件配置未发现风险", false)
	}
	return audit
}
