package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	mjmMaxFindings         = 48
	mjmMaxJarBytes         = 256 * 1024 * 1024
	mjmMaxManifest         = 64 * 1024
	mjmMaxEntries          = 20000
	mjmMaxMods             = 256
	mjmReasonOK            = "ok"
	mjmReasonMissing       = "missing"
	mjmReasonSymlink       = "symlink"
	mjmReasonTooLarge      = "too-large"
	mjmReasonBadJar        = "bad-jar"
	mjmReasonEntryOverflow = "entry-overflow"
	mjmReasonAgent         = "agent-class"
	mjmReasonClassPath     = "class-path-escape"
	mjmReasonMainClass     = "bad-main-class"
	mjmReasonManifestLarge = "manifest-too-large"
	mjmReasonBadName       = "bad-jar-name"
)

type ModJarFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type ModJarManifestAudit struct {
	ServerDir string
	Jars      int
	Findings  []ModJarFinding
}

func (a *ModJarManifestAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= mjmMaxFindings {
		return
	}
	a.Findings = append(a.Findings, ModJarFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *ModJarManifestAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ModJarFinding) bool { return f.Blocking })
}

func (a *ModJarManifestAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if f.Reason != mjmReasonOK && !f.Blocking {
			return true
		}
	}
	return false
}

func (a *ModJarManifestAudit) Describe() string {
	return describeFindings(a.Findings, func(f ModJarFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func mjmParseManifest(text string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var current string
	var builder strings.Builder
	flush := func() {
		if current == "" {
			return
		}
		value := strings.TrimSpace(builder.String())
		if _, exists := out[current]; !exists {
			out[current] = value
		}
		current = ""
		builder.Reset()
	}
	for _, line := range lines {
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, " ") && current != "" {
			builder.WriteString(strings.TrimPrefix(line, " "))
			continue
		}
		flush()
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		current = strings.ToLower(strings.TrimSpace(line[:idx]))
		builder.WriteString(strings.TrimSpace(line[idx+1:]))
	}
	flush()
	return out
}

func mjmClassPathEntries(value string) []string {
	items := make([]string, 0, 8)
	for _, raw := range strings.Split(value, " ") {
		for _, piece := range strings.Split(raw, ",") {
			trimmed := strings.TrimSpace(piece)
			if trimmed != "" {
				items = append(items, trimmed)
			}
		}
	}
	return items
}

func mjmUnsafeClassPathEntry(entry string) bool {
	lower := strings.ToLower(entry)
	if strings.Contains(lower, "..") {
		return true
	}
	if strings.Contains(lower, "://") || strings.HasPrefix(lower, "http") || strings.HasPrefix(lower, "file:") {
		return true
	}
	if strings.HasPrefix(entry, "/") || strings.HasPrefix(entry, "\\") {
		return true
	}
	if len(entry) > 2 && entry[1] == ':' {
		return true
	}
	if strings.ContainsAny(entry, "\x00\n\r") {
		return true
	}
	return false
}

func mjmScanJar(a *ModJarManifestAudit, root, rel string, size int64) {
	path := filepath.Join(root, rel)
	reader, err := zip.OpenReader(path)
	if err != nil {
		a.add(rel, mjmReasonBadJar, "无法作为 ZIP/JAR 打开", false)
		return
	}
	defer reader.Close()
	if len(reader.File) > mjmMaxEntries {
		a.add(rel, mjmReasonEntryOverflow, fmt.Sprintf("条目数 %d 超过 %d", len(reader.File), mjmMaxEntries), false)
		return
	}
	found := false
	for _, entry := range reader.File {
		name := strings.ToLower(entry.Name)
		if name != "meta-inf/manifest.mf" {
			continue
		}
		found = true
		if entry.UncompressedSize64 > mjmMaxManifest {
			a.add(rel, mjmReasonManifestLarge, fmt.Sprintf("MANIFEST.MF 解压后 %d 字节", entry.UncompressedSize64), false)
			return
		}
		file, ferr := entry.Open()
		if ferr != nil {
			a.add(rel, mjmReasonBadJar, "MANIFEST.MF 无法读取", false)
			return
		}
		data := make([]byte, 0, mjmMaxManifest)
		buf := make([]byte, 4096)
		for {
			n, rerr := file.Read(buf)
			if n > 0 {
				data = append(data, buf[:n]...)
				if len(data) > mjmMaxManifest {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		file.Close()
		mjmCheckManifest(a, rel, string(data))
		return
	}
	if !found {
		a.add(rel, mjmReasonMissing, "JAR 内无 META-INF/MANIFEST.MF", false)
	}
}

func mjmCheckManifest(a *ModJarManifestAudit, rel, text string) {
	if strings.TrimSpace(text) == "" {
		a.add(rel, mjmReasonBadJar, "MANIFEST.MF 为空", false)
		return
	}
	attrs := mjmParseManifest(text)
	for _, key := range []string{"premain-class", "agent-class", "launcher-agent-class"} {
		value, ok := attrs[key]
		if !ok || value == "" {
			continue
		}
		a.add(rel, mjmReasonAgent, key+"="+value, true)
	}
	if value, ok := attrs["class-path"]; ok {
		for _, entry := range mjmClassPathEntries(value) {
			if mjmUnsafeClassPathEntry(entry) {
				a.add(rel, mjmReasonClassPath, "Class-Path 指向外部路径: "+entry, true)
				break
			}
			if !strings.HasPrefix(entry, "META-INF/") && !strings.HasSuffix(strings.ToLower(entry), ".jar") {
				a.add(rel, mjmReasonClassPath, "Class-Path 条目不是归档内依赖: "+entry, false)
				break
			}
		}
	}
	if value, ok := attrs["main-class"]; ok {
		if strings.Contains(value, "..") || strings.Contains(value, "/") || strings.Contains(value, "\\") {
			a.add(rel, mjmReasonMainClass, "Main-Class 含路径写法: "+value, false)
		}
	}
}

func mjmScanDir(a *ModJarManifestAudit, root string) {
	dir := filepath.Join(root, "mods")
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return
	}
	entries, derr := os.ReadDir(dir)
	if derr != nil {
		a.add("mods", mjmReasonBadJar, "mods 目录不可读", false)
		return
	}
	count := 0
	for _, entry := range entries {
		if count >= mjmMaxMods {
			a.add("mods", mjmReasonEntryOverflow, fmt.Sprintf("已扫描 %d 个条目后截断", mjmMaxMods), false)
			return
		}
		count++
		name := entry.Name()
		rel := filepath.ToSlash(filepath.Join("mods", name))
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".jar") {
			continue
		}
		if len(name) > 160 {
			a.add(rel, mjmReasonBadName, "文件名超长", false)
			continue
		}
		info, ierr := entry.Info()
		if ierr != nil {
			a.add(rel, mjmReasonBadJar, "无法读取文件信息", false)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			a.add(rel, mjmReasonSymlink, "模组文件为符号链接", true)
			continue
		}
		if info.Size() > mjmMaxJarBytes {
			a.add(rel, mjmReasonTooLarge, fmt.Sprintf("文件体积 %d 超过上限", info.Size()), false)
			continue
		}
		a.Jars++
		mjmScanJar(a, root, rel, info.Size())
	}
}

func AuditModJarManifests(serverDir string) *ModJarManifestAudit {
	a := &ModJarManifestAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", mjmReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", mjmReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", mjmReasonMissing, "服务器目录不存在", false)
		return a
	}
	mjmScanDir(a, serverDir)
	if a.Jars == 0 && len(a.Findings) == 0 {
		a.add(".", mjmReasonMissing, "未发现 mods 目录或 JAR", false)
	}
	return a
}
