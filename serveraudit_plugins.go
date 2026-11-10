package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
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

type ModJarFinding = auditFinding
type ModJarManifestAudit struct {
	ServerDir string
	Jars      int
	Findings  []ModJarFinding
}

func (a *ModJarManifestAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, mjmMaxFindings, ModJarFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *ModJarManifestAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ModJarFinding) bool { return f.Blocking })
}
func (a *ModJarManifestAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f ModJarFinding) bool { return f.Reason != mjmReasonOK && !f.Blocking })
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

const (
	modManifestReasonOK              = "ok"
	modManifestReasonSymlink         = "symlink"
	modManifestReasonNotRegular      = "not-regular"
	modManifestReasonTooLarge        = "too-large"
	modManifestReasonBadZip          = "bad-zip"
	modManifestReasonTooManyEntries  = "too-many-entries"
	modManifestReasonEntryTooLarge   = "entry-too-large"
	modManifestReasonBombRatio       = "bomb-ratio"
	modManifestReasonSuspiciousEntry = "suspicious-entry"
	modManifestReasonDuplicateEntry  = "duplicate-entry"
	modManifestReasonBadMetadata     = "bad-metadata"
	modManifestReasonDuplicateID     = "duplicate-mod-id"
	modManifestReasonEmptyArchive    = "empty-archive"
	modManifestMaxJars               = 2000
	modManifestMaxJarBytes           = int64(512) << 20
	modManifestMaxEntries            = 20000
	modManifestMaxEntryBytes         = uint64(256) << 20
	modManifestMaxRatio              = 200
	modManifestMaxMetadataBytes      = int64(512) << 10
)

type ModManifestFinding struct {
	File     string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}
type ModManifestAudit struct {
	Dir      string
	Present  bool
	Jars     int
	Entries  int
	Findings []ModManifestFinding
}

func (audit ModManifestAudit) Blocking() bool {
	return anyBlocking(audit.Findings, func(f ModManifestFinding) bool { return f.Blocking })
}

func (audit ModManifestAudit) HasWarnings() bool {
	return len(audit.Findings) > 0 && !audit.Blocking()
}

func (audit ModManifestAudit) Codes() []string {
	return findingCodes(audit.Findings, func(f ModManifestFinding) string { return f.Reason })
}

func (audit ModManifestAudit) Describe() string {
	if len(audit.Findings) == 0 {
		return "模组清单校验通过"
	}
	parts := make([]string, 0, len(audit.Findings))
	for _, finding := range audit.Findings {
		entry := finding.Entry
		if entry == "" {
			entry = finding.File
		}
		parts = append(parts, fmt.Sprintf("%s:%s(%s)", finding.File, entry, finding.Detail))
	}
	return strings.Join(parts, "；")
}

func isManifestModJar(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".jar") && !strings.HasSuffix(lower, ".jar.disabled")
}

func (audit *ModManifestAudit) scanJar(fileName, jarPath string, modIDs map[string]string) {
	reader, err := zip.OpenReader(jarPath)
	if err != nil {
		audit.Findings = append(audit.Findings, ModManifestFinding{
			File: fileName, Reason: modManifestReasonBadZip,
			Detail: "无法作为 zip 打开", Blocking: true,
		})
		return
	}
	defer reader.Close()
	if len(reader.File) == 0 {
		audit.Findings = append(audit.Findings, ModManifestFinding{
			File: fileName, Reason: modManifestReasonEmptyArchive,
			Detail: "压缩包内没有任何条目", Blocking: true,
		})
		return
	}
	seen := map[string]bool{}
	for _, entry := range reader.File {
		audit.Entries++
		if audit.Entries > modManifestMaxEntries {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: fileName, Reason: modManifestReasonTooManyEntries,
				Detail: "累计条目数超过上限", Blocking: true,
			})
			return
		}
		if suspiciousServerJarEntry(entry.Name) {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: fileName, Entry: entry.Name, Reason: modManifestReasonSuspiciousEntry,
				Detail: "条目路径可疑", Blocking: true,
			})
		}
		if seen[entry.Name] {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: fileName, Entry: entry.Name, Reason: modManifestReasonDuplicateEntry,
				Detail: "压缩包内条目重名，解压行为不确定", Blocking: true,
			})
		}
		seen[entry.Name] = true
		if entry.UncompressedSize64 > modManifestMaxEntryBytes {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: fileName, Entry: entry.Name, Reason: modManifestReasonEntryTooLarge,
				Detail: fmt.Sprintf("解压后 %d 字节超过上限", entry.UncompressedSize64), Blocking: true,
			})
		} else if entry.CompressedSize64 > 0 && entry.UncompressedSize64/entry.CompressedSize64 > modManifestMaxRatio {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: fileName, Entry: entry.Name, Reason: modManifestReasonBombRatio,
				Detail: "压缩比超过阈值", Blocking: true,
			})
		}
		if id, ok := modIDFromEntry(entry); ok {
			if id == "" {
				audit.Findings = append(audit.Findings, ModManifestFinding{
					File: fileName, Entry: entry.Name, Reason: modManifestReasonBadMetadata,
					Detail: "模组元数据无法解析出 id", Blocking: false,
				})
				continue
			}
			if previous, exists := modIDs[id]; exists {
				audit.Findings = append(audit.Findings, ModManifestFinding{
					File: fileName, Entry: id, Reason: modManifestReasonDuplicateID,
					Detail: fmt.Sprintf("id %q 与 %s 冲突", id, previous), Blocking: false,
				})
				continue
			}
			modIDs[id] = fileName
		}
	}
}

func modIDFromEntry(entry *zip.File) (string, bool) {
	name := strings.ToLower(entry.Name)
	base := filepath.Base(name)
	switch {
	case base == "fabric.mod.json", base == "quilt.mod.json":
	case base == "mods.toml" && strings.Contains(name, "meta-inf/"):
	case base == "mcmod.info":
	default:
		return "", false
	}
	if entry.UncompressedSize64 > uint64(modManifestMaxMetadataBytes) {
		return "", true
	}
	reader, err := entry.Open()
	if err != nil {
		return "", true
	}
	defer reader.Close()
	data := make([]byte, 0, modManifestMaxMetadataBytes)
	buf := make([]byte, 4096)
	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if int64(len(data)) > modManifestMaxMetadataBytes {
				return "", true
			}
		}
		if readErr != nil {
			break
		}
	}
	return extractModID(base, data), true
}

func extractModID(base string, data []byte) string {
	switch base {
	case "fabric.mod.json", "quilt.mod.json":
		var payload struct {
			ID    string `json:"id"`
			Quilt struct {
				ID string `json:"id"`
			} `json:"quilt_loader"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return ""
		}
		if strings.TrimSpace(payload.ID) != "" {
			return strings.TrimSpace(payload.ID)
		}
		return strings.TrimSpace(payload.Quilt.ID)
	case "mods.toml":
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "modId") {
				_, value, _, ok := splitPropertyPair(trimmed)
				if ok {
					return strings.Trim(strings.TrimSpace(value), "\"'")
				}
			}
		}
	case "mcmod.info":
		var payload []struct {
			ModID string `json:"modid"`
		}
		if err := json.Unmarshal(data, &payload); err != nil || len(payload) == 0 {
			return ""
		}
		return strings.TrimSpace(payload[0].ModID)
	}
	return ""
}

func AuditServerModManifest(modsDir string) (ModManifestAudit, error) {
	audit := ModManifestAudit{Dir: modsDir}
	if strings.TrimSpace(modsDir) == "" {
		return audit, nil
	}
	info, err := os.Lstat(modsDir)
	if os.IsNotExist(err) {
		return audit, nil
	}
	if err != nil {
		return audit, err
	}
	audit.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, ModManifestFinding{
			File: modsDir, Reason: modManifestReasonSymlink,
			Detail: "mods 目录本身是符号链接", Blocking: true,
		})
		return audit, nil
	}
	if !info.IsDir() {
		audit.Findings = append(audit.Findings, ModManifestFinding{
			File: modsDir, Reason: modManifestReasonNotRegular,
			Detail: "mods 路径不是目录", Blocking: true,
		})
		return audit, nil
	}

	entries, err := os.ReadDir(modsDir)
	if err != nil {
		return audit, err
	}
	modIDs := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || !isManifestModJar(entry.Name()) {
			continue
		}
		if audit.Jars >= modManifestMaxJars {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: modsDir, Reason: modManifestReasonTooManyEntries,
				Detail: fmt.Sprintf("jar 数量超过 %d", modManifestMaxJars), Blocking: true,
			})
			break
		}
		audit.Jars++
		jarPath := filepath.Join(modsDir, entry.Name())
		jarInfo, statErr := os.Lstat(jarPath)
		if statErr != nil {
			return audit, statErr
		}
		if jarInfo.Mode()&os.ModeSymlink != 0 {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: entry.Name(), Reason: modManifestReasonSymlink,
				Detail: "jar 是符号链接，实际内容可被外部替换", Blocking: true,
			})
			continue
		}
		if !jarInfo.Mode().IsRegular() {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: entry.Name(), Reason: modManifestReasonNotRegular,
				Detail: "jar 不是普通文件", Blocking: true,
			})
			continue
		}
		if jarInfo.Size() > modManifestMaxJarBytes {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: entry.Name(), Reason: modManifestReasonTooLarge,
				Detail: fmt.Sprintf("jar 体积 %d 超过上限", jarInfo.Size()), Blocking: true,
			})
			continue
		}
		audit.scanJar(entry.Name(), jarPath, modIDs)
	}
	return audit, nil
}

const (
	snmMaxFindings = 18
	snmMaxFile     = 256 * 1024
	snmMiss        = "properties-missing"
	snmRead        = "properties-unreadable"
	snmOffline     = "online-mode-off"
	snmSecureOff   = "secure-profile-off"
	snmProxyOpen   = "proxy-connections-allowed"
	snmCompressOff = "compression-threshold-disabled"
	snmCompressLow = "compression-threshold-too-low"
	snmEmpty       = "properties-empty"
	snmLink        = "properties-symlink"
	snmBom         = "properties-bom"
)

type OnlineModeFinding = auditFinding
type OnlineModeAudit struct {
	ServerDir string
	Findings  []OnlineModeFinding
}

func (a *OnlineModeAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, snmMaxFindings, OnlineModeFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *OnlineModeAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f OnlineModeFinding) bool { return f.Blocking })
}
func (a *OnlineModeAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *OnlineModeAudit) Describe() string {
	return describeReasonDetail("在线认证配置未发现风险", a.Findings, 12)
}

func snmReadProps(serverDir string, a *OnlineModeAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(snmMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(snmRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(snmLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, snmMaxFile)
	if err != nil {
		a.add(snmRead, err.Error(), true)
		return nil, false
	}
	text := string(data)
	if strings.HasPrefix(text, "\ufeff") {
		a.add(snmBom, "属性文件带 BOM 头，首键可能失效", false)
		text = strings.TrimPrefix(text, "\ufeff")
	}
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(snmEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}

func snmBool(props map[string]string, key string) (bool, bool) {
	return propsBoolValue(props, key)
}

func AuditServerOnlineMode(serverDir string) *OnlineModeAudit {
	a := &OnlineModeAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(snmMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := snmReadProps(serverDir, a)
	if !ok {
		return a
	}
	if online, has := snmBool(props, "online-mode"); has && !online {
		a.add(snmOffline, "离线模式允许任意伪造用户名与 UUID", true)
	}
	if secure, has := snmBool(props, "enforce-secure-profile"); has && !secure {
		a.add(snmSecureOff, "关闭聊天签名校验，可被重放冒充", false)
	}
	if proxy, has := snmBool(props, "prevent-proxy-connections"); has && !proxy {
		if online, has2 := snmBool(props, "online-mode"); has2 && online {
			a.add(snmProxyOpen, "在线模式却允许代理转发连接", false)
		}
	}
	raw, has := props["network-compression-threshold"]
	if has {
		value, parsed := cfgParseInt(raw)
		if parsed {
			if value < 0 {
				a.add(snmCompressOff, "关闭网络压缩，放大带宽消耗", false)
			} else if value >= 0 && value < 64 {
				a.add(snmCompressLow, fmt.Sprintf("压缩阈值 %d 过低，易被压缩炸弹拖垮", value), false)
			}
		} else {
			a.add(snmCompressLow, "压缩阈值不是整数: "+cfgStripQuotes(raw), false)
		}
	}
	return a
}

const (
	pluginReasonOK          = "ok"
	pluginReasonSymlink     = "symlink"
	pluginReasonNotDir      = "not-directory"
	pluginReasonTooLarge    = "too-large"
	pluginReasonBadZip      = "bad-zip"
	pluginReasonBadEntry    = "bad-entry"
	pluginReasonTooMany     = "too-many-entries"
	pluginReasonBadManifest = "bad-manifest"
	pluginReasonDuplicate   = "duplicate-name"
	pluginReasonExecutable  = "executable-file"
	pluginMaxCount          = 256
	pluginMaxBytes          = 64 << 20
	pluginMaxEntries        = 10000
	pluginMaxDirEntries     = 2048
	pluginMaxManifestBytes  = 256 << 10
	pluginMaxNameRunes      = 64
	pluginMaxClassChars     = 255
)

var pluginDangerousExt = map[string]bool{
	".exe": true, ".bat": true, ".cmd": true, ".com": true,
	".scr": true, ".ps1": true, ".sh": true, ".dll": true,
	".vbs": true, ".js": true, ".jar.exe": true,
}

type PluginFinding struct {
	Name     string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerPluginAudit struct {
	Dir      string
	Present  bool
	Jars     int
	Findings []PluginFinding
}

type pluginManifest struct {
	Name string
	Main string
}

func (a ServerPluginAudit) Blocking() bool {
	for _, finding := range a.Findings {
		if finding.Blocking {
			return true
		}
	}
	return false
}

func (a ServerPluginAudit) HasWarnings() bool {
	for _, finding := range a.Findings {
		if !finding.Blocking {
			return true
		}
	}
	return false
}

func (a ServerPluginAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("插件目录共 %d 个 jar，未发现异常", a.Jars)
	}
	parts := make([]string, 0, len(a.Findings))
	for _, finding := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s: %s", finding.Name, finding.Detail))
	}
	return strings.Join(parts, "；")
}

func auditPluginJar(path, name string) ([]PluginFinding, pluginManifest, error) {
	manifest := pluginManifest{}
	info, err := os.Stat(path)
	if err != nil {
		return nil, manifest, err
	}
	if info.Size() > pluginMaxBytes {
		return []PluginFinding{{
			Name: name, Reason: pluginReasonTooLarge,
			Detail: fmt.Sprintf("jar 体积 %d 超过上限 %d", info.Size(), pluginMaxBytes), Blocking: true,
		}}, manifest, nil
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		return []PluginFinding{{
			Name: name, Reason: pluginReasonBadZip, Detail: "jar 无法作为 zip 打开", Blocking: true,
		}}, manifest, nil
	}
	defer reader.Close()
	if len(reader.File) > pluginMaxEntries {
		return []PluginFinding{{
			Name: name, Reason: pluginReasonTooMany,
			Detail: fmt.Sprintf("jar 条目数 %d 超过上限 %d", len(reader.File), pluginMaxEntries), Blocking: true,
		}}, manifest, nil
	}
	findings := []PluginFinding{}
	var manifestFile *zip.File
	for _, file := range reader.File {
		if suspiciousServerJarEntry(file.Name) {
			findings = append(findings, PluginFinding{
				Name: name, Reason: pluginReasonBadEntry,
				Detail: fmt.Sprintf("jar 条目路径越界: %s", file.Name), Blocking: true,
			})
			continue
		}
		if strings.EqualFold(filepath.Base(file.Name), "plugin.yml") && manifestFile == nil {
			manifestFile = file
		}
	}
	if manifestFile == nil {
		findings = append(findings, PluginFinding{
			Name: name, Reason: pluginReasonBadManifest, Detail: "缺少 plugin.yml", Blocking: false,
		})
		return findings, manifest, nil
	}
	if manifestFile.UncompressedSize64 > pluginMaxManifestBytes {
		findings = append(findings, PluginFinding{
			Name: name, Reason: pluginReasonBadManifest, Detail: "plugin.yml 体积超限", Blocking: true,
		})
		return findings, manifest, nil
	}
	raw, err := readZipEntryBounded(manifestFile, pluginMaxManifestBytes)
	if err != nil {
		return nil, manifest, err
	}
	parsed, parseFindings := parsePluginManifest(name, raw)
	findings = append(findings, parseFindings...)
	manifest = parsed
	return findings, manifest, nil
}

func readZipEntryBounded(file *zip.File, limit int64) ([]byte, error) {
	handle, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	buffer := make([]byte, 0, 4096)
	for int64(len(buffer)) <= limit {
		chunk := make([]byte, 4096)
		n, readErr := handle.Read(chunk)
		buffer = append(buffer, chunk[:n]...)
		if readErr != nil {
			break
		}
		if n == 0 {
			break
		}
	}
	if int64(len(buffer)) > limit {
		return nil, fmt.Errorf("条目超过 %d 字节", limit)
	}
	return buffer, nil
}

func parsePluginManifest(jarName string, raw []byte) (pluginManifest, []PluginFinding) {
	manifest := pluginManifest{}
	findings := []PluginFinding{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, _, ok := splitPropertyPair(trimmed)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "name":
			manifest.Name = strings.TrimSpace(value)
			if manifest.Name == "" {
				findings = append(findings, PluginFinding{
					Name: jarName, Reason: pluginReasonBadManifest, Detail: "plugin.yml 的 name 为空", Blocking: true,
				})
			} else if utf8.RuneCountInString(manifest.Name) > pluginMaxNameRunes {
				findings = append(findings, PluginFinding{
					Name: jarName, Reason: pluginReasonBadManifest, Detail: "plugin.yml 的 name 过长", Blocking: true,
				})
			}
		case "main":
			manifest.Main = strings.TrimSpace(value)
			if !validJavaClassName(manifest.Main) {
				findings = append(findings, PluginFinding{
					Name: jarName, Reason: pluginReasonBadManifest,
					Detail: fmt.Sprintf("plugin.yml 的 main 不是合法类名: %s", manifest.Main), Blocking: true,
				})
			}
		}
	}
	if manifest.Main == "" {
		findings = append(findings, PluginFinding{
			Name: jarName, Reason: pluginReasonBadManifest, Detail: "plugin.yml 缺少 main", Blocking: true,
		})
	}
	return manifest, findings
}

func validJavaClassName(value string) bool {
	if value == "" || len(value) > pluginMaxClassChars {
		return false
	}
	for _, segment := range strings.Split(value, ".") {
		if segment == "" {
			return false
		}
		for index, ch := range segment {
			isLetter := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
			isDigit := ch >= '0' && ch <= '9'
			if index == 0 && isDigit {
				return false
			}
			if !isLetter && !isDigit && ch != '_' && ch != '$' {
				return false
			}
		}
	}
	return true
}

func AuditServerPlugins(serverDir string) (ServerPluginAudit, error) {
	audit := ServerPluginAudit{Dir: filepath.Join(serverDir, "plugins")}
	info, err := os.Lstat(audit.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return audit, nil
		}
		return audit, err
	}
	audit.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, PluginFinding{
			Name: "plugins", Reason: pluginReasonSymlink, Detail: "插件目录是符号链接", Blocking: true,
		})
		return audit, nil
	}
	if !info.IsDir() {
		audit.Findings = append(audit.Findings, PluginFinding{
			Name: "plugins", Reason: pluginReasonNotDir, Detail: "插件路径不是目录", Blocking: true,
		})
		return audit, nil
	}
	entries, err := os.ReadDir(audit.Dir)
	if err != nil {
		return audit, err
	}
	if len(entries) > pluginMaxDirEntries {
		audit.Findings = append(audit.Findings, PluginFinding{
			Name: "plugins", Reason: pluginReasonTooMany,
			Detail: fmt.Sprintf("目录条目 %d 超过上限 %d", len(entries), pluginMaxDirEntries), Blocking: true,
		})
	}
	names := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(audit.Dir, name)
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return audit, statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.Findings = append(audit.Findings, PluginFinding{
				Name: name, Reason: pluginReasonSymlink, Detail: "插件条目是符号链接", Blocking: true,
			})
			continue
		}
		if entry.IsDir() {
			continue
		}
		lower := strings.ToLower(name)
		if pluginDangerousExt[lower] {
			audit.Findings = append(audit.Findings, PluginFinding{
				Name: name, Reason: pluginReasonExecutable, Detail: "插件目录出现可执行文件", Blocking: true,
			})
			continue
		}
		if !strings.HasSuffix(lower, ".jar") {
			audit.Findings = append(audit.Findings, PluginFinding{
				Name: name, Reason: pluginReasonBadEntry, Detail: "插件目录出现非 jar 文件", Blocking: false,
			})
			continue
		}
		audit.Jars++
		if audit.Jars > pluginMaxCount {
			audit.Findings = append(audit.Findings, PluginFinding{
				Name: name, Reason: pluginReasonTooMany,
				Detail: fmt.Sprintf("jar 数量超过上限 %d", pluginMaxCount), Blocking: true,
			})
			continue
		}
		findings, manifest, err := auditPluginJar(path, name)
		if err != nil {
			return audit, err
		}
		audit.Findings = append(audit.Findings, findings...)
		if manifest.Name != "" {
			key := strings.ToLower(manifest.Name)
			if first, ok := names[key]; ok {
				audit.Findings = append(audit.Findings, PluginFinding{
					Name: name, Reason: pluginReasonDuplicate,
					Detail: fmt.Sprintf("插件名 %q 与 %s 重复", manifest.Name, first), Blocking: true,
				})
			} else {
				names[key] = name
			}
		}
	}
	sort.SliceStable(audit.Findings, func(i, j int) bool { return audit.Findings[i].Name < audit.Findings[j].Name })
	return audit, nil
}

const (
	pcReasonOK              = "ok"
	pcReasonMissing         = "missing"
	pcReasonUnreadable      = "unreadable"
	pcReasonTooLarge        = "too-large"
	pcReasonSymlink         = "symlink"
	pcReasonTooMany         = "too-many"
	pcReasonDangerousToggle = "dangerous-toggle"
	pcReasonPlaintextSecret = "plaintext-secret"
	pcReasonWorldReadable   = "world-readable"
	pcReasonDepthExceeded   = "depth-exceeded"

	pcMaxFileBytes = 512 << 10
	pcMaxFiles     = 512
	pcMaxDepth     = 3
	pcMaxFindings  = 96
	pcMaxLineScan  = 4096
)

var pcConfigExts = []string{".yml", ".yaml", ".json", ".toml", ".conf", ".properties"}

var pcDangerousKeys = []string{
	"bypass-permissions",
	"bypass_permissions",
	"bypasspermissions",
	"allow-unsafe",
	"allow_unsafe",
	"allowunsafe",
	"allow-flight",
	"allow_flight",
	"allowflight",
	"debug",
	"disable-auth",
	"disable_auth",
	"disableauth",
	"skip-auth",
	"auth-bypass",
	"op-override",
}

var pcSecretKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"api-key",
	"apikey",
	"api_key",
	"access-key",
	"private-key",
	"rcon-password",
}

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

type PluginConfigFinding = auditFinding

type PluginConfigAudit struct {
	Dir      string
	Files    []string
	Findings []PluginConfigFinding
}

func (a PluginConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginConfigFinding) bool { return f.Blocking })
}

func (a PluginConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginConfigFinding) bool { return !f.Blocking && f.Reason != pcReasonOK })
}

func (a PluginConfigAudit) Codes() []string {
	return findingCodesSkip(a.Findings, pcReasonOK, func(f PluginConfigFinding) string { return f.Reason })
}

func (a PluginConfigAudit) Describe() string {
	return describeLabeledFindings("未发现插件配置", a.Findings, 4, "",
		func(f PluginConfigFinding) string { return f.File },
		func(f PluginConfigFinding) string { return f.Reason })
}

func (a PluginConfigAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f PluginConfigFinding) bool { return f.Blocking }, func(f PluginConfigFinding) bool { return !f.Blocking && f.Reason != pcReasonOK })
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}

func (a *PluginConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pcMaxFindings, PluginConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

const (
	mpeMaxFindings      = 48
	mpeMaxJarBytes      = 512 * 1024 * 1024
	mpeMaxEntryBytes    = 256 * 1024 * 1024
	mpeMaxEntries       = 20000
	mpeMaxRatio         = 1000
	mpeRatioMinBytes    = 1024 * 1024
	mpeMaxNestedJars    = 8
	mpeMaxPlugins       = 256
	mpeReasonOK         = "ok"
	mpeReasonMissing    = "missing"
	mpeReasonSymlink    = "symlink"
	mpeReasonTooLarge   = "too-large"
	mpeReasonBadJar     = "bad-jar"
	mpeReasonTraversal  = "entry-traversal"
	mpeReasonDuplicate  = "duplicate-entry"
	mpeReasonEntryLarge = "entry-too-large"
	mpeReasonBomb       = "zip-bomb"
	mpeReasonEntryCount = "entry-overflow"
	mpeReasonNested     = "nested-jars"
	mpeReasonBadName    = "bad-jar-name"
)

type PluginJarEntryFinding = auditFinding
type PluginJarEntryAudit struct {
	ServerDir string
	Jars      int
	Findings  []PluginJarEntryFinding
}

func (a *PluginJarEntryAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, mpeMaxFindings, PluginJarEntryFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func mpeScanDir(a *PluginJarEntryAudit, root string) {
	dir := filepath.Join(root, "plugins")
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return
	}
	entries, derr := os.ReadDir(dir)
	if derr != nil {
		a.add("plugins", mpeReasonBadJar, "plugins 目录不可读", false)
		return
	}
	count := 0
	for _, entry := range entries {
		if count >= mpeMaxPlugins {
			a.add("plugins", mpeReasonEntryCount, fmt.Sprintf("已扫描 %d 个条目后截断", mpeMaxPlugins), false)
			return
		}
		count++
		name := entry.Name()
		rel := filepath.ToSlash(filepath.Join("plugins", name))
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".jar") {
			continue
		}
		if len(name) > 160 {
			a.add(rel, mpeReasonBadName, "文件名超长", false)
			continue
		}
		info, ierr := entry.Info()
		if ierr != nil {
			a.add(rel, mpeReasonBadJar, "无法读取文件信息", false)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			a.add(rel, mpeReasonSymlink, "插件文件为符号链接", true)
			continue
		}
		if info.Size() > mpeMaxJarBytes {
			a.add(rel, mpeReasonTooLarge, fmt.Sprintf("文件体积 %d 超过上限", info.Size()), false)
			continue
		}
		a.Jars++
		mpeScanJar(a, root, rel)
	}
}

func AuditPluginJarEntries(serverDir string) *PluginJarEntryAudit {
	a := &PluginJarEntryAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", mpeReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", mpeReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", mpeReasonMissing, "服务器目录不存在", false)
		return a
	}
	mpeScanDir(a, serverDir)
	if a.Jars == 0 && len(a.Findings) == 0 {
		a.add(".", mpeReasonMissing, "未发现 plugins 目录或 JAR", false)
	}
	return a
}

func (a *PluginJarEntryAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginJarEntryFinding) bool { return f.Blocking })
}

func (a *PluginJarEntryAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginJarEntryFinding) bool { return f.Reason != mpeReasonOK && !f.Blocking })
}

func (a *PluginJarEntryAudit) Describe() string {
	return describeFindings(a.Findings, func(f PluginJarEntryFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func mpeEntryUnsafe(name string) bool {
	if name == "" {
		return true
	}
	if strings.ContainsAny(name, "\x00\n\r") {
		return true
	}
	lower := strings.ToLower(name)
	if strings.Contains(lower, "../") || strings.Contains(lower, "..\\") {
		return true
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
		return true
	}
	if len(name) > 1 && name[1] == ':' {
		return true
	}
	if strings.Contains(name, "\\") {
		return true
	}
	trimmed := strings.TrimPrefix(lower, "./")
	if strings.HasPrefix(trimmed, "../") {
		return true
	}
	return false
}

func mpeScanJar(a *PluginJarEntryAudit, root, rel string) {
	path := filepath.Join(root, rel)
	reader, err := zip.OpenReader(path)
	if err != nil {
		a.add(rel, mpeReasonBadJar, "无法作为 ZIP/JAR 打开", false)
		return
	}
	defer reader.Close()
	if len(reader.File) > mpeMaxEntries {
		a.add(rel, mpeReasonEntryCount, fmt.Sprintf("条目数 %d 超过 %d", len(reader.File), mpeMaxEntries), false)
		return
	}
	seen := map[string]bool{}
	nested := 0
	dupCount := 0
	var dupSample string
	for _, entry := range reader.File {
		name := entry.Name
		if mpeEntryUnsafe(name) {
			a.add(rel, mpeReasonTraversal, "条目路径越界: "+name, true)
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			dupCount++
			if dupSample == "" {
				dupSample = name
			}
		}
		seen[key] = true
		if strings.HasSuffix(key, ".jar") {
			nested++
		}
		if entry.UncompressedSize64 > mpeMaxEntryBytes {
			a.add(rel, mpeReasonEntryLarge, fmt.Sprintf("条目 %s 解压后 %d 字节", name, entry.UncompressedSize64), true)
			continue
		}
		if entry.UncompressedSize64 >= mpeRatioMinBytes && entry.CompressedSize64 > 0 {
			ratio := entry.UncompressedSize64 / entry.CompressedSize64
			if ratio > mpeMaxRatio {
				a.add(rel, mpeReasonBomb, fmt.Sprintf("条目 %s 压缩比 %d", name, ratio), true)
			}
		}
	}
	if dupCount > 0 {
		a.add(rel, mpeReasonDuplicate, fmt.Sprintf("重复条目 %d 个, 首个 %s", dupCount, dupSample), false)
	}
	if nested > mpeMaxNestedJars {
		a.add(rel, mpeReasonNested, fmt.Sprintf("内嵌 JAR %d 个", nested), false)
	}
}

const (
	pjReasonOK           = "ok"
	pjReasonMissing      = "missing"
	pjReasonEmpty        = "empty-plugins-dir"
	pjReasonUnreadable   = "unreadable"
	pjReasonTooLarge     = "too-large"
	pjReasonTooMany      = "too-many"
	pjReasonSymlink      = "symlink"
	pjReasonBadName      = "bad-name"
	pjReasonNoDescriptor = "missing-plugin-yml"
	pjReasonNoMain       = "missing-main-class"
	pjReasonBadMain      = "bad-main-class"
	pjReasonNestedJar    = "nested-jar"
	pjReasonExecBit      = "executable-bit"
	pjReasonShellClass   = "shell-capable-main"
	pjReasonUnsigned     = "unsigned"
	pjReasonWeakDigest   = "weak-digest"
	pjReasonDuplicateJar = "duplicate-jar"
	pjReasonTooManyFiles = "too-many-entries"

	pjMaxJarBytes    = 64 << 20
	pjMaxJars        = 128
	pjMaxEntries     = 4096
	pjMaxFindings    = 160
	pjMaxMainLen     = 200
	pjMaxNestedDepth = 2
)

var pjSelectedPaths = []string{
	"META-INF/MANIFEST.MF",
	"META-INF/",
	"plugin.yml",
	"paper-plugin.yml",
	"bungee.yml",
	"velocity-plugin.json",
}

var pjShellyMainTokens = []string{
	"runtime.exec",
	"processbuilder",
	"scriptengine",
	"shell",
	"cmd",
	"exec",
}

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

type PluginJarFinding struct {
	Jar      string
	Reason   string
	Detail   string
	Blocking bool
}
type PluginJarAudit struct {
	Dir      string
	Jars     []string
	Findings []PluginJarFinding
}

func (a PluginJarAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginJarFinding) bool { return f.Blocking })
}
func (a PluginJarAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginJarFinding) bool { return !f.Blocking && f.Reason != pjReasonOK })
}

func (a PluginJarAudit) Describe() string {
	return describeTaggedFindings("插件包结构未发现风险", a.Findings, pjReasonOK, "plugins", pjMaxFindings,
		func(f PluginJarFinding) string { return f.Reason },
		func(f PluginJarFinding) string { return f.Jar },
		func(f PluginJarFinding) string { return f.Detail })
}

func (a *PluginJarAudit) add(jar, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pjMaxFindings, PluginJarFinding{Jar: jar, Reason: reason, Detail: detail, Blocking: blocking})
}

const (
	spmMaxFindings      = 48
	spmReasonOK         = "ok"
	spmReasonMissing    = "missing"
	spmReasonEnabled    = "telemetry-enabled"
	spmReasonCleartext  = "telemetry-cleartext-endpoint"
	spmReasonCreds      = "telemetry-endpoint-credentials"
	spmReasonIdentifier = "telemetry-stable-identifier"
	spmReasonBadValue   = "bad-value"
	spmReasonScanNote   = "scan"
	spmReasonDSN        = "telemetry-dsn"
	spmReasonIP         = "telemetry-ip-collection"
)

type PluginMetricsFinding = auditFinding
type PluginMetricsAudit struct {
	ServerDir   string
	ConfigCount int
	Findings    []PluginMetricsFinding
}

func (a *PluginMetricsAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spmMaxFindings, PluginMetricsFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *PluginMetricsAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginMetricsFinding) bool { return f.Blocking })
}
func (a *PluginMetricsAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginMetricsFinding) bool {
		return f.Reason != spmReasonOK && f.Reason != spmReasonScanNote && !f.Blocking
	})
}

func (a *PluginMetricsAudit) Describe() string {
	return describeFindings(a.Findings, func(f PluginMetricsFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func spmToggleKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"metrics", "bstats", "telemetry", "usage-stats", "usage_stats",
		"analytics", "tracking", "anonymous-statistics", "statistics", "sentry",
	})
}

func spmEndpointKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"metrics-url", "metrics_url", "telemetry-url", "telemetry_url",
		"analytics-url", "analytics_url", "bstats-url", "bstats_url",
		"statistics-url", "sentry-dsn", "dsn",
	})
}

func spmIdentifierKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"metrics-uuid", "metrics_uuid", "server-uuid", "server_uuid",
		"installation-id", "install-id", "instance-id",
	})
}

func spmIPKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"collect-player-ips", "send-player-ips", "log-player-ips",
		"store-ips", "include-ip", "include_ips", "send-ip",
	})
}

func spmCheckEndpoints(a *PluginMetricsAudit, cfg spxConfig) {
	for _, key := range spmEndpointKeys(cfg.Flat) {
		value := strings.TrimSpace(cfg.Flat[key])
		if value == "" {
			a.add(cfg.Rel, spmReasonBadValue, "遥测端点为空: "+key, false)
			continue
		}
		if strings.HasSuffix(key, "dsn") && strings.HasPrefix(strings.ToLower(value), "https://") {
			a.add(cfg.Rel, spmReasonDSN, "配置了外部错误上报 DSN: "+key, false)
			continue
		}
		kind, risky := spxURLRisk(value)
		switch kind {
		case "cleartext":
			a.add(cfg.Rel, spmReasonCleartext, "遥测端点使用明文 HTTP: "+key, true)
		case "credentials":
			a.add(cfg.Rel, spmReasonCreds, "遥测端点内嵌凭据: "+key, false)
		case "local-or-legacy":
			a.add(cfg.Rel, spmReasonCleartext, "遥测端点使用本地或旧式协议: "+key, true)
		case "path-shape":
			a.add(cfg.Rel, spmReasonCreds, "遥测端点包含路径穿越片段: "+key, true)
		case "https":
			if strings.Contains(strings.ToLower(value), "sentry") {
				a.add(cfg.Rel, spmReasonDSN, "配置了外部错误上报 DSN: "+key, false)
			}
		}

		if risky {
			continue
		}
	}
}

func spmCheckToggles(a *PluginMetricsAudit, cfg spxConfig) {
	enabled := false
	for _, key := range spmToggleKeys(cfg.Flat) {
		value := cfg.Flat[key]
		on, known := spxBool(value)
		switch {
		case !known:
			lower := strings.ToLower(strings.TrimSpace(value))
			if lower == "https://bstats.org" || strings.HasPrefix(lower, "https://") {
				a.add(cfg.Rel, spmReasonEnabled, "遥测地址已配置: "+key, false)
				enabled = true
				continue
			}
			if key != "sentry" && key != "analytics" && key != "tracking" && key != "statistics" {
				continue
			}
			a.add(cfg.Rel, spmReasonBadValue, "遥测开关取值非法: "+key+"="+value, false)
		case on:
			enabled = true
			a.add(cfg.Rel, spmReasonEnabled, "插件启用了外部遥测: "+key, false)
		}
	}
	for _, key := range spmIdentifierKeys(cfg.Flat) {
		value := strings.TrimSpace(cfg.Flat[key])
		if value == "" {
			continue
		}
		a.add(cfg.Rel, spmReasonIdentifier, "遥测携带稳定安装标识: "+key, false)
	}
	for _, key := range spmIPKeys(cfg.Flat) {
		on, known := spxBool(cfg.Flat[key])
		if known && on {
			a.add(cfg.Rel, spmReasonIP, "插件配置收集玩家 IP: "+key, false)
		}
	}
	if enabled {
		a.add(cfg.Rel, spmReasonEnabled, "该插件会把运行数据发送到外部服务", false)
	}
}

func AuditServerPluginMetrics(serverDir string) *PluginMetricsAudit {
	a := &PluginMetricsAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", spmReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", spmReasonScanNote, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", spmReasonMissing, "服务器目录不存在", false)
		return a
	}

	scan := spxScanPluginConfigs(serverDir)
	for _, note := range scan.Notes {
		a.add(note.File, note.Reason, note.Detail, note.Blocking)
	}
	a.ConfigCount = len(scan.Configs)
	if len(scan.Configs) == 0 {
		a.add("plugins", spmReasonMissing, "未找到可审计的插件配置文件", false)
		return a
	}
	for _, cfg := range scan.Configs {
		spmCheckEndpoints(a, cfg)
		spmCheckToggles(a, cfg)
	}
	a.add("plugins", spmReasonOK, fmt.Sprintf("共扫描 %d 个插件配置", a.ConfigCount), false)
	return a
}

const (
	spuMaxFindings    = 48
	spuReasonOK       = "ok"
	spuReasonMissing  = "missing"
	spuReasonAuto     = "auto-update-enabled"
	spuReasonInsecure = "update-source-insecure"
	spuReasonCreds    = "update-source-credentials"
	spuReasonPath     = "update-source-path-shape"
	spuReasonNoSource = "update-without-source"
	spuReasonChannel  = "update-channel-unstable"
	spuReasonBadValue = "bad-value"
	spuReasonScanNote = "scan"
)

type PluginUpdateFinding = auditFinding
type PluginUpdateAudit struct {
	ServerDir   string
	ConfigCount int
	Findings    []PluginUpdateFinding
}

func (a *PluginUpdateAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spuMaxFindings, PluginUpdateFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PluginUpdateAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginUpdateFinding) bool { return f.Blocking })
}

func (a *PluginUpdateAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginUpdateFinding) bool {
		return f.Reason != spuReasonOK && f.Reason != spuReasonScanNote && !f.Blocking
	})
}

func (a *PluginUpdateAudit) Describe() string {
	return describeFindings(a.Findings, func(f PluginUpdateFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func spuAutoUpdateKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"auto-update", "auto_update", "update-check", "update_check",
		"check-for-updates", "check_for_updates", "update-on-start",
	})
}

func spuSourceKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"update-url", "update_url", "download-url", "download_url",
		"update-check-url", "update_check_url", "update-repository", "repository-url",
	})
}

func spuCheckConfig(a *PluginUpdateAudit, cfg spxConfig) {
	autoKeys := spuAutoUpdateKeys(cfg.Flat)
	sourceKeys := spuSourceKeys(cfg.Flat)

	autoEnabled := false
	for _, key := range autoKeys {
		enabled, known := spxBool(cfg.Flat[key])
		switch {
		case !known:
			a.add(cfg.Rel, spuReasonBadValue, "自动更新开关取值非法: "+key+"="+cfg.Flat[key], false)
		case enabled:
			autoEnabled = true
			a.add(cfg.Rel, spuReasonAuto, "插件启用自动更新，更新包未经过本地校验: "+key, false)
		}
	}

	sourceCount := 0
	for _, key := range sourceKeys {
		kind, risky := spxURLRisk(cfg.Flat[key])
		switch kind {
		case "empty":
			a.add(cfg.Rel, spuReasonBadValue, "更新源地址为空: "+key, false)
			continue
		case "credentials":
			a.add(cfg.Rel, spuReasonCreds, "更新源地址内嵌凭据: "+key, true)
		case "path-shape":
			a.add(cfg.Rel, spuReasonPath, "更新源地址包含路径穿越或反斜杠: "+key, true)
		case "cleartext":
			a.add(cfg.Rel, spuReasonInsecure, "更新源使用明文 HTTP: "+key, true)
		case "local-or-legacy":
			a.add(cfg.Rel, spuReasonInsecure, "更新源使用本地或旧式协议: "+key, true)
		case "https":
			sourceCount++
		}
		if risky {
			continue
		}
		if strings.Contains(strings.ToLower(cfg.Flat[key]), "github.com") {
			sourceCount++
		}
	}

	if autoEnabled && sourceCount == 0 {
		a.add(cfg.Rel, spuReasonNoSource, "自动更新已启用但没有声明可信更新源", false)
	}

	channelKeys := spxKeysWithSuffix(cfg.Flat, []string{"update-channel", "update_channel", "release-channel", "channel"})
	for _, key := range channelKeys {
		value := strings.ToLower(strings.TrimSpace(cfg.Flat[key]))
		switch value {
		case "", "stable", "release", "production":
		case "dev", "dev-build", "nightly", "snapshot", "beta", "alpha", "canary":
			a.add(cfg.Rel, spuReasonChannel, "更新通道为不稳定分支: "+key+"="+value, false)
		default:
			if strings.Contains(value, "dev") || strings.Contains(value, "beta") || strings.Contains(value, "snapshot") {
				a.add(cfg.Rel, spuReasonChannel, "更新通道含有不稳定标识: "+key+"="+value, false)
			}
		}
	}
}

func AuditServerPluginUpdates(serverDir string) *PluginUpdateAudit {
	a := &PluginUpdateAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", spuReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", spuReasonScanNote, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", spuReasonMissing, "服务器目录不存在", false)
		return a
	}

	scan := spxScanPluginConfigs(serverDir)
	for _, note := range scan.Notes {
		a.add(note.File, note.Reason, note.Detail, note.Blocking)
	}
	a.ConfigCount = len(scan.Configs)
	if len(scan.Configs) == 0 {
		a.add("plugins", spuReasonMissing, "未找到可审计的插件配置文件", false)
		return a
	}
	for _, cfg := range scan.Configs {
		spuCheckConfig(a, cfg)
	}
	a.add("plugins", spuReasonOK, fmt.Sprintf("共扫描 %d 个插件配置", a.ConfigCount), false)
	return a
}
