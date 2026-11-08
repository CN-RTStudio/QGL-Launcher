package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

const (
	jarCpReasonOK          = "ok"
	jarCpReasonMissing     = "missing"
	jarCpReasonUnreadable  = "unreadable"
	jarCpReasonTooLarge    = "too-large"
	jarCpReasonTooMany     = "too-many"
	jarCpReasonNotZip      = "not-zip"
	jarCpReasonNoManifest  = "manifest-missing"
	jarCpReasonAbsolute    = "classpath-absolute"
	jarCpReasonTraversal   = "classpath-traversal"
	jarCpReasonRemote      = "classpath-remote"
	jarCpReasonDuplicate   = "classpath-duplicate"
	jarCpReasonAgentEntry  = "agent-entry"
	jarCpMaxJars           = 120
	jarCpMaxManifestBytes  = 512 << 10
	jarCpMaxEntries        = 64
	jarCpMaxFindingsPerJar = 24
	jarCpClassPathAttr     = "class-path:"
	jarCpManifestPath      = "META-INF/MANIFEST.MF"
)

var jarCpScanRoots = []string{
	".",
	"plugins",
	filepath.Join("plugins", "update"),
}

type JarCPFinding struct {
	Jar      string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

type JarClassPathAudit struct {
	Dir      string
	Jars     int
	Findings []JarCPFinding
}

func (a JarClassPathAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a JarClassPathAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != jarCpReasonOK {
			return true
		}
	}
	return false
}

func (a JarClassPathAudit) Codes() []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, f := range a.Findings {
		if f.Reason == jarCpReasonOK || seen[f.Reason] {
			continue
		}
		seen[f.Reason] = true
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}

func (a JarClassPathAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("已扫描 %d 个 jar，未发现 Class-Path 注入", a.Jars)
	}
	parts := []string{}
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s[%s](%s)", f.Jar, f.Entry, f.Reason))
		if len(parts) >= 5 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a JarClassPathAudit) Summary() string {
	blocking := 0
	warnings := 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != jarCpReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("jars=%d findings=%d blocking=%d warnings=%d", a.Jars, len(a.Findings), blocking, warnings)
}

func (a *JarClassPathAudit) add(jar, entry, reason, detail string, blocking bool) {
	if len(a.Findings) >= jarCpMaxFindingsPerJar*jarCpMaxJars {
		return
	}
	a.Findings = append(a.Findings, JarCPFinding{Jar: jar, Entry: entry, Reason: reason, Detail: detail, Blocking: blocking})
}

func jarCPUnfoldManifest(data []byte) []string {
	raw := strings.ReplaceAll(string(data), "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := []string{}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, " ") && len(lines) > 0 {
			lines[len(lines)-1] += strings.TrimPrefix(line, " ")
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func jarCPEntries(value string) []string {
	out := []string{}
	for _, part := range strings.Fields(value) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func jarCPDriveLetter(entry string) bool {
	if len(entry) < 2 || entry[1] != ':' {
		return false
	}
	c := entry[0]
	return unicode.IsLetter(rune(c)) && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')
}

func jarCPIsAbsolute(entry string) bool {
	if strings.HasPrefix(entry, "/") || strings.HasPrefix(entry, `\\`) {
		return true
	}
	return jarCPDriveLetter(entry)
}

func jarCPIsRemote(entry string) bool {
	lower := strings.ToLower(entry)
	for _, scheme := range []string{"http://", "https://", "ftp://", "jar:", "file:"} {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	return false
}

func jarCPHasTraversal(entry string) bool {
	normalized := strings.ReplaceAll(entry, `\\`, "/")
	for _, seg := range strings.Split(normalized, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

func jarCPScanManifest(audit *JarClassPathAudit, jar string, data []byte) bool {
	lines := jarCPUnfoldManifest(data)
	classPath := ""
	agent := false
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, jarCpClassPathAttr) {
			classPath = strings.TrimSpace(line[len(jarCpClassPathAttr):])
		}
		if strings.HasPrefix(lower, "premain-class:") || strings.HasPrefix(lower, "agent-class:") {
			agent = true
		}
		if strings.HasPrefix(lower, "launcher-agent-class:") {
			agent = true
		}
	}
	if agent {
		audit.add(jar, "manifest", jarCpReasonAgentEntry, "jar 声明了 java agent 入口，需确认来源可信", false)
	}
	if classPath == "" {
		return false
	}
	entries := jarCPEntries(classPath)
	if len(entries) > jarCpMaxEntries {
		audit.add(jar, "class-path", jarCpReasonTooMany, fmt.Sprintf("Class-Path 条目数量 %d 超过上限", len(entries)), true)
	}
	seen := map[string]bool{}
	flagged := 0
	for _, entry := range entries {
		if seen[entry] {
			audit.add(jar, entry, jarCpReasonDuplicate, "Class-Path 重复条目", false)
			flagged++
			continue
		}
		seen[entry] = true
		switch {
		case jarCPIsRemote(entry):
			audit.add(jar, entry, jarCpReasonRemote, "Class-Path 指向远程或 file 协议，可加载任意路径", true)
		case jarCPIsAbsolute(entry):
			audit.add(jar, entry, jarCpReasonAbsolute, "Class-Path 使用绝对路径，可逃逸服务器目录", true)
		case jarCPHasTraversal(entry):
			audit.add(jar, entry, jarCpReasonTraversal, "Class-Path 包含 .. 片段，可逃逸服务器目录", true)
		}
		flagged++
		if flagged >= jarCpMaxFindingsPerJar {
			audit.add(jar, "class-path", jarCpReasonTooMany, "单 jar Class-Path 告警过多，后续条目未展开", false)
			break
		}
	}
	return true
}

func jarCPInspect(audit *JarClassPathAudit, path, display string) {
	info, err := os.Lstat(path)
	if err != nil {
		audit.add(display, "", jarCpReasonUnreadable, "jar 不可访问", false)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(display, "", jarCpReasonUnreadable, "jar 是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(display, "", jarCpReasonUnreadable, "jar 不是普通文件", true)
		return
	}
	if info.Size() > jarCpMaxManifestBytes<<12 {
		audit.add(display, "", jarCpReasonTooLarge, "jar 体积异常", true)
		return
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		audit.add(display, "", jarCpReasonNotZip, "无法解析为 zip/jar", true)
		return
	}
	defer reader.Close()
	var manifest *zip.File
	for _, f := range reader.File {
		if strings.EqualFold(f.Name, jarCpManifestPath) {
			manifest = f
			break
		}
	}
	if manifest == nil {
		audit.add(display, "", jarCpReasonNoManifest, "jar 缺少清单文件", false)
		return
	}
	if manifest.UncompressedSize64 > jarCpMaxManifestBytes {
		audit.add(display, "", jarCpReasonTooLarge, "清单文件超过上限", true)
		return
	}
	rc, err := manifest.Open()
	if err != nil {
		audit.add(display, "", jarCpReasonUnreadable, "清单文件不可读", true)
		return
	}
	defer rc.Close()
	buf := make([]byte, jarCpMaxManifestBytes)
	n, err := rc.Read(buf)
	if err != nil && n == 0 {
		audit.add(display, "", jarCpReasonUnreadable, "清单文件读取失败", true)
		return
	}
	if !jarCPScanManifest(audit, display, buf[:n]) {
		return
	}
}

func AuditServerJarClassPath(serverDir string) JarClassPathAudit {
	audit := JarClassPathAudit{Dir: serverDir}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		audit.add("server", "", jarCpReasonMissing, "服务器目录不存在", true)
		return audit
	}
	scanned := 0
	for _, root := range jarCpScanRoots {
		dir := filepath.Join(serverDir, root)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if scanned >= jarCpMaxJars {
				audit.add(root, "", jarCpReasonTooMany, "jar 数量超过扫描上限", true)
				break
			}
			lower := strings.ToLower(entry.Name())
			if entry.IsDir() || !strings.HasSuffix(lower, ".jar") {
				continue
			}
			display := entry.Name()
			if root != "." {
				display = filepath.Join(root, entry.Name())
			}
			scanned++
			audit.Jars++
			jarCPInspect(&audit, filepath.Join(dir, entry.Name()), display)
		}
	}
	if len(audit.Findings) == 0 {
		audit.add("", "", jarCpReasonOK, "Class-Path 均为相对且无远程引用", false)
	}
	return audit
}
