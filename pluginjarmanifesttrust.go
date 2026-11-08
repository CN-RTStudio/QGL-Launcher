package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	pjmMaxFindings   = 16
	pjmMaxJars       = 512
	pjmMaxJarSize    = 256 * 1024 * 1024
	pjmMaxManifest   = 512 * 1024
	pjmMiss          = "plugin-dir-missing"
	pjmRead          = "plugin-dir-unreadable"
	pjmLink          = "plugin-dir-symlink"
	pjmJarLink       = "plugin-jar-symlink"
	pjmJarOpen       = "plugin-jar-unreadable"
	pjmJarSize       = "plugin-jar-oversized"
	pjmAgent         = "plugin-manifest-agent"
	pjmClassPath     = "plugin-manifest-classpath"
	pjmMainClass     = "plugin-manifest-main"
	pjmBadAttribute  = "plugin-manifest-attribute"
	pjmManifestEmpty = "plugin-manifest-empty"
)

type PjmFinding struct {
	Jar      string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

type PjmAudit struct {
	ServerDir  string
	Jars       int
	Manifests  int
	AgentAttrs int
	Findings   []PjmFinding
}

func (a *PjmAudit) add(jar, entry, reason, detail string, blocking bool) {
	if len(a.Findings) >= pjmMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PjmFinding{Jar: jar, Entry: entry, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PjmAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *PjmAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *PjmAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("插件清单属性未发现自动加载或外部类路径，%d 个 jar，%d 份清单", a.Jars, a.Manifests)
	}
	sorted := make([]PjmFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Entry < sorted[j].Entry
	})
	parts := make([]string, 0, len(sorted))
	for i, f := range sorted {
		if i >= 8 {
			parts = append(parts, fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		parts = append(parts, f.Reason)
	}
	return strings.Join(parts, "；")
}

func pjmUnfold(raw string) map[string]string {
	attrs := make(map[string]string)
	var key string
	var val strings.Builder
	flush := func() {
		if key != "" {
			attrs[key] = strings.TrimSpace(val.String())
		}
		key = ""
		val.Reset()
	}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, " ") {
			if key != "" {
				val.WriteString(strings.TrimPrefix(line, " "))
			}
			continue
		}
		flush()
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key = strings.TrimSpace(line[:idx])
		val.WriteString(strings.TrimSpace(line[idx+1:]))
	}
	flush()
	return attrs
}

func pjmClassPathEntry(raw string) bool {
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "://") {
		return true
	}
	if strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "\\") {
		return true
	}
	if len(raw) > 1 && raw[1] == ':' {
		return true
	}
	for _, seg := range strings.FieldsFunc(raw, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}

func AuditPluginManifestTrust(serverDir string) *PjmAudit {
	a := &PjmAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("plugins", "", pjmMiss, "未配置服务器目录", false)
		return a
	}

	dir := filepath.Join(serverDir, "plugins")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		a.add("plugins", "", pjmMiss, "缺少插件目录", false)
		return a
	}
	link, err := isSymlinkOrSpecial(dir)
	if err != nil {
		a.add("plugins", "", pjmRead, err.Error(), true)
		return a
	}
	if link {
		a.add("plugins", "", pjmLink, "插件目录是符号链接或特殊文件", true)
		return a
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add("plugins", "", pjmRead, "无法读取插件目录", true)
		return a
	}

	agentKeys := []string{"Agent-Class", "Premain-Class", "Launcher-Agent-Class"}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(name), ".jar") {
			continue
		}
		a.Jars++
		path := filepath.Join(dir, name)
		link, err := isSymlinkOrSpecial(path)
		if err != nil {
			a.add(name, "", pjmJarOpen, err.Error(), true)
			continue
		}
		if link {
			a.add(name, "", pjmJarLink, "jar 是符号链接或特殊文件", true)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			a.add(name, "", pjmJarOpen, "jar 无法访问", true)
			continue
		}
		if info.Size() > pjmMaxJarSize {
			a.add(name, "", pjmJarSize, fmt.Sprintf("jar %d 字节超过上限", info.Size()), false)
			continue
		}

		archive, err := zip.OpenReader(path)
		if err != nil {
			a.add(name, "", pjmJarOpen, "jar 不是合法 zip", true)
			continue
		}

		for _, file := range archive.File {
			entryName := strings.ToUpper(strings.TrimPrefix(file.Name, "/"))
			if entryName != "META-INF/MANIFEST.MF" {
				continue
			}
			a.Manifests++
			if file.UncompressedSize64 > uint64(pjmMaxManifest) {
				a.add(name, file.Name, pjmBadAttribute, "清单体积超过上限", false)
				continue
			}
			rc, err := file.Open()
			if err != nil {
				a.add(name, file.Name, pjmJarOpen, "无法读取清单", true)
				break
			}
			body, err := io.ReadAll(io.LimitReader(rc, pjmMaxManifest))
			rc.Close()
			if err != nil {
				a.add(name, file.Name, pjmJarOpen, "读取清单失败", true)
				break
			}
			if len(strings.TrimSpace(string(body))) == 0 {
				a.add(name, file.Name, pjmManifestEmpty, "清单为空", false)
				continue
			}

			attrs := pjmUnfold(string(body))
			for _, key := range agentKeys {
				if v, ok := attrs[key]; ok && v != "" {
					a.AgentAttrs++
					a.add(name, file.Name, pjmAgent, key+"="+v, true)
				}
			}
			if v, ok := attrs["Class-Path"]; ok && v != "" {
				for _, ref := range strings.Fields(v) {
					if pjmClassPathEntry(ref) {
						a.add(name, file.Name, pjmClassPath, "外部类路径 "+ref, true)
					}
				}
			}
			if v, ok := attrs["Main-Class"]; ok && v != "" {
				a.add(name, file.Name, pjmMainClass, "Main-Class="+v, false)
			}
		}
		archive.Close()
	}

	if a.Jars > pjmMaxJars {
		a.add("plugins", "", pjmJarSize, fmt.Sprintf("jar 数量 %d 超过上限", a.Jars), false)
	}
	return a
}
