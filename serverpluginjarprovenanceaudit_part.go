package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
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

func pjReadEntry(reader *zip.ReadCloser, name string) (string, error) {
	for _, entry := range reader.File {
		if entry.Name != name {
			continue
		}
		if entry.UncompressedSize64 > 1<<20 {
			return "", fmt.Errorf("描述文件超长")
		}
		f, err := entry.Open()
		if err != nil {
			return "", err
		}
		defer f.Close()
		buf := make([]byte, entry.UncompressedSize64)
		n, err := f.Read(buf)
		if err != nil && n == 0 {
			return "", err
		}
		return string(buf[:n]), nil
	}
	return "", fmt.Errorf("缺少 %s", name)
}

func AuditServerPluginJars(serverDir string) PluginJarAudit {
	audit := PluginJarAudit{Dir: serverDir}
	root := filepath.Join(serverDir, "plugins")
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("", pjReasonMissing, "服务器目录不存在", true)
		return audit
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		audit.add("plugins", pjReasonMissing, "未发现 plugins 目录", false)
		return audit
	}
	seen := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".jar") {
			continue
		}
		if len(audit.Jars) >= pjMaxJars {
			audit.add("plugins", pjReasonTooMany, "插件包数量超过预算", true)
			break
		}
		rel := filepath.Join("plugins", name)
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if err != nil {
			audit.add(rel, pjReasonUnreadable, "无法读取插件包", true)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(rel, pjReasonSymlink, "插件包是符号链接", true)
			continue
		}
		if info.Mode().Perm()&0o111 != 0 {
			audit.add(rel, pjReasonExecBit, "插件包带可执行位", false)
		}
		if strings.Contains(name, " ") || strings.HasPrefix(name, ".") {
			audit.add(rel, pjReasonBadName, "插件包文件名可疑", false)
		}
		stem := strings.TrimSuffix(lower, ".jar")
		if prev, ok := seen[stem]; ok {
			audit.add(rel, pjReasonDuplicateJar, fmt.Sprintf("与 %s 同名重复", prev), false)
		}
		seen[stem] = name
		audit.Jars = append(audit.Jars, rel)
		pjInspectJar(&audit, rel, path, info.Size())
	}
	if len(audit.Jars) == 0 {
		audit.add("plugins", pjReasonEmpty, "未发现插件包", false)
	}
	if len(audit.Findings) == 0 {
		audit.add("", pjReasonOK, "插件包结构未发现风险", false)
	}
	return audit
}
