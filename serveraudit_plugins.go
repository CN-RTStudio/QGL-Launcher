package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
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

func (a *JarClassPathAudit) add(jar, entry, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, jarCpMaxFindingsPerJar*jarCpMaxJars, JarCPFinding{Jar: jar, Entry: entry, Reason: reason, Detail: detail, Blocking: blocking})
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

type JarClassPathAudit struct {
	Dir      string
	Jars     int
	Findings []JarCPFinding
}

func (a JarClassPathAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JarCPFinding) bool { return f.Blocking })
}

func (a JarClassPathAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f JarCPFinding) bool { return !f.Blocking && f.Reason != jarCpReasonOK })
}

func (a JarClassPathAudit) Codes() []string {
	return findingCodesSkip(a.Findings, jarCpReasonOK, func(f JarCPFinding) string { return f.Reason })
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
	blocking, warnings := auditTally(a.Findings, func(f JarCPFinding) bool { return f.Blocking }, func(f JarCPFinding) bool { return !f.Blocking && f.Reason != jarCpReasonOK })
	return fmt.Sprintf("jars=%d findings=%d blocking=%d warnings=%d", a.Jars, len(a.Findings), blocking, warnings)
}

const (
	libReasonOK               = "ok"
	libReasonMissing          = "missing"
	libReasonUnreadable       = "unreadable"
	libReasonTooLarge         = "too-large"
	libReasonSymlink          = "symlink"
	libReasonTooMany          = "too-many"
	libReasonNotAJar          = "not-a-jar"
	libReasonDuplicateVersion = "duplicate-version"
	libReasonShadowCopy       = "shadow-copy"
	libReasonBadName          = "bad-name"
	libReasonWorldWritable    = "world-writable"

	libMaxFileBytes = 256 << 20
	libMaxFiles     = 512
	libMaxDepth     = 6
	libMaxFindings  = 96
)

var libRoots = []string{"libs", "libraries"}

type LibraryFinding = auditFinding

type LibraryAudit struct {
	Dir      string
	Jars     []string
	Findings []LibraryFinding
}

func (a LibraryAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f LibraryFinding) bool { return f.Blocking })
}

func (a LibraryAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f LibraryFinding) bool { return !f.Blocking && f.Reason != libReasonOK })
}

func (a LibraryAudit) Codes() []string {
	return findingCodesSkip(a.Findings, libReasonOK, func(f LibraryFinding) string { return f.Reason })
}

func libLooksVersion(segment string) bool {
	digits, alpha := 0, 0
	for i := 0; i < len(segment); i++ {
		ch := segment[i]
		if ch >= '0' && ch <= '9' {
			digits++
			continue
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			alpha++
		}
	}
	if digits == 0 {
		return false
	}
	return digits >= alpha
}

func libNameSane(name string) bool {
	if name == "" || len(name) > 160 {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if ch < 0x20 || ch == 0x7f {
			return false
		}
	}
	return true
}

func libLooksLikeZip(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 4)
	n, err := f.Read(head)
	if err != nil && n < 4 {
		return false
	}
	return string(head) == "PK\x03\x04" || string(head) == "PK\x05\x06"
}

func libCollect(audit *LibraryAudit, root, rel string, depth int) {
	if depth > libMaxDepth {
		audit.add(rel, libReasonTooMany, "依赖库目录层级超出预算", true)
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		audit.add(rel, libReasonUnreadable, "依赖库目录不可读", true)
		return
	}
	for _, entry := range entries {
		if len(audit.Jars) >= libMaxFiles {
			audit.add(rel, libReasonTooMany, "依赖库文件数量超过预算", true)
			return
		}
		childPath := filepath.Join(root, entry.Name())
		childRel := filepath.Join(rel, entry.Name())
		if entry.IsDir() {
			libCollect(audit, childPath, childRel, depth+1)
			continue
		}
		lower := strings.ToLower(entry.Name())
		if !strings.HasSuffix(lower, ".jar") {
			if strings.HasSuffix(lower, ".jar.old") || strings.HasSuffix(lower, ".jar.disabled") || strings.HasSuffix(lower, ".jar.bak") {
				audit.add(childRel, libReasonShadowCopy, "遗留的禁用/备份 jar", false)
			}
			continue
		}
		if !libNameSane(entry.Name()) {
			audit.add(childRel, libReasonBadName, "jar 名含控制字符", true)
			continue
		}
		info, err := os.Lstat(childPath)
		if err != nil {
			audit.add(childRel, libReasonUnreadable, "jar 不可访问", true)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(childRel, libReasonSymlink, "jar 是符号链接", true)
			continue
		}
		if !info.Mode().IsRegular() {
			audit.add(childRel, libReasonUnreadable, "jar 不是普通文件", true)
			continue
		}
		if info.Size() > libMaxFileBytes {
			audit.add(childRel, libReasonTooLarge, "jar 超过体积预算", true)
			continue
		}
		if info.Mode().Perm()&0o022 != 0 {
			audit.add(childRel, libReasonWorldWritable, "jar 对其他用户可写", false)
		}
		if !libLooksLikeZip(childPath) {
			audit.add(childRel, libReasonNotAJar, "文件头不是 zip/jar", false)
		}
		audit.Jars = append(audit.Jars, childRel)
	}
}

func AuditServerLibraries(serverDir string) LibraryAudit {
	audit := LibraryAudit{Dir: serverDir}
	keys := map[string]string{}
	for _, rootName := range libRoots {
		root := filepath.Join(serverDir, rootName)
		if _, err := os.Stat(root); err != nil {
			continue
		}
		libCollect(&audit, root, rootName, 0)
	}
	if len(audit.Jars) == 0 {
		if len(audit.Findings) == 0 {
			audit.add("", libReasonMissing, "未发现 libs/libraries 目录", false)
		}
		audit.add("", libReasonOK, "无依赖库归档", false)
		return audit
	}
	for _, jar := range audit.Jars {
		key := libArtifactKey(jar)
		if key == "" {
			continue
		}
		if prev, ok := keys[key]; ok {
			audit.add(jar, libReasonDuplicateVersion, "同一构件多版本共存，与 "+prev+" 冲突", false)
			continue
		}
		keys[key] = jar
	}
	if len(audit.Findings) == 0 {
		audit.add("", libReasonOK, "依赖库结构正常", false)
	}
	return audit
}

func (a LibraryAudit) Describe() string {
	return describeLabeledFindings("未发现依赖库", a.Findings, 4, "",
		func(f LibraryFinding) string { return f.File },
		func(f LibraryFinding) string { return f.Reason })
}
func (a LibraryAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f LibraryFinding) bool { return f.Blocking }, func(f LibraryFinding) bool { return !f.Blocking && f.Reason != libReasonOK })
	return fmt.Sprintf("jars=%d findings=%d blocking=%d warnings=%d", len(a.Jars), len(a.Findings), blocking, warnings)
}

func (a *LibraryAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, libMaxFindings, LibraryFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func libArtifactKey(name string) string {
	lower := strings.ToLower(strings.TrimSuffix(filepath.Base(name), filepath.Ext(name)))
	for _, marker := range []string{"-sources", "-javadoc", "-natives"} {
		lower = strings.TrimSuffix(lower, marker)
	}
	segments := strings.Split(lower, "-")
	kept := []string{}
	for _, segment := range segments {
		if segment == "" || libLooksVersion(segment) {
			continue
		}
		kept = append(kept, segment)
	}
	if len(kept) == 0 {
		return lower
	}
	return strings.Join(kept, "-")
}
