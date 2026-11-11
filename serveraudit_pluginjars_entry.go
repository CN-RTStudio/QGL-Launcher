package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
