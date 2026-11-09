package main

import (
	"archive/zip"
	"fmt"
	"strings"
)

func pjDescriptorName(entries map[string]bool) string {
	for _, name := range []string{"plugin.yml", "paper-plugin.yml", "bungee.yml", "velocity-plugin.json"} {
		if entries[name] {
			return name
		}
	}
	return ""
}

func pjMainClass(descriptor, body string) (string, bool) {
	if strings.HasSuffix(descriptor, ".json") {
		const key = "\"main\""
		idx := strings.Index(body, key)
		if idx < 0 {
			return "", false
		}
		rest := body[idx+len(key):]
		colon := strings.Index(rest, ":")
		if colon < 0 {
			return "", false
		}
		rest = rest[colon+1:]
		quote := strings.Index(rest, "\"")
		if quote < 0 {
			return "", false
		}
		rest = rest[quote+1:]
		end := strings.Index(rest, "\"")
		if end < 0 {
			return "", false
		}
		return strings.TrimSpace(rest[:end]), true
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "main:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "main:"))
		value = strings.Trim(value, "'\"")
		return value, true
	}
	return "", false
}

func pjMainLooksBad(main string) (bad, shelly bool) {
	if main == "" {
		return true, false
	}
	if len(main) > pjMaxMainLen {
		return true, false
	}
	if strings.Contains(main, "..") || strings.HasPrefix(main, "/") || strings.ContainsAny(main, " \t") {
		return true, false
	}
	dots := strings.Count(main, ".")
	if dots < 1 {
		return true, false
	}
	lower := strings.ToLower(main)
	for _, token := range pjShellyMainTokens {
		if strings.Contains(lower, token) {
			return false, true
		}
	}
	return false, false
}

func pjInspectJar(audit *PluginJarAudit, rel, path string, size int64) {
	if size <= 0 {
		audit.add(rel, pjReasonEmpty, "插件包为空", true)
		return
	}
	if size > pjMaxJarBytes {
		audit.add(rel, pjReasonTooLarge, "插件包体积超过预算", true)
		return
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		audit.add(rel, pjReasonUnreadable, "插件包不是可读的 zip", true)
		return
	}
	defer reader.Close()
	entries := map[string]bool{}
	nested := 0
	weakDigest := ""
	for _, entry := range reader.File {
		name := entry.Name
		if strings.HasSuffix(name, "/") {
			continue
		}
		if len(entries) >= pjMaxEntries {
			audit.add(rel, pjReasonTooManyFiles, "条目数量超过预算", true)
			break
		}
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
			audit.add(rel, pjReasonBadName, fmt.Sprintf("条目路径越界: %s", name), true)
			continue
		}
		entries[name] = true
		if strings.HasSuffix(strings.ToLower(name), ".jar") {
			nested++
			if nested > pjMaxNestedDepth {
				audit.add(rel, pjReasonNestedJar, "嵌套插件包数量超过预算", true)
			}
		}
		if strings.HasSuffix(strings.ToUpper(name), ".SF") || strings.HasSuffix(strings.ToUpper(name), ".RSA") {
			_ = entry
		}
	}
	descriptor := pjDescriptorName(entries)
	if descriptor == "" {
		audit.add(rel, pjReasonNoDescriptor, "缺少 plugin.yml / velocity-plugin.json", true)
		return
	}
	if entries[strings.ToUpper("META-INF/MANIFEST.MF")] || entries["META-INF/MANIFEST.MF"] {
		body, err := pjReadEntry(reader, "META-INF/MANIFEST.MF")
		if err == nil {
			upper := strings.ToUpper(body)
			if strings.Contains(upper, "SHA1-DIGEST") || strings.Contains(upper, "MD5-DIGEST") {
				weakDigest = "清单使用 SHA1/MD5 摘要"
			}
		}
	}
	if weakDigest != "" {
		audit.add(rel, pjReasonWeakDigest, weakDigest, true)
	}
	if !entries["META-INF/PLUGIN.SF"] && !entries["META-INF/PLUGIN.RSA"] &&
		!entries["META-INF/MANIFEST.SF"] && !entries["META-INF/MANIFEST.RSA"] {
		audit.add(rel, pjReasonUnsigned, "插件包未签名", false)
	}
	body, err := pjReadEntry(reader, descriptor)
	if err != nil {
		audit.add(rel, pjReasonUnreadable, "无法读取插件描述文件", true)
		return
	}
	main, ok := pjMainClass(descriptor, body)
	if !ok {
		audit.add(rel, pjReasonNoMain, "插件描述未声明 main 类", true)
		return
	}
	bad, shelly := pjMainLooksBad(main)
	if bad {
		audit.add(rel, pjReasonBadMain, fmt.Sprintf("main 类名非法: %s", main), true)
		return
	}
	if shelly {
		audit.add(rel, pjReasonShellClass, fmt.Sprintf("main 类名疑似命令执行入口: %s", main), false)
	}
}
