package main

import (
	"archive/zip"
	"encoding/json"
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

func runJarRootAudit(serverDir, reasonMissing, reasonSymlink, emptyHint string,
	add func(file, reason, detail string, blocking bool),
	scan func(dir string),
	jars func() int,
	findingsLen func() int) {
	if serverDir == "" {
		add(".", reasonMissing, "未配置服务器目录", false)
		return
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		add(".", reasonSymlink, "服务器目录为符号链接", true)
		return
	}
	if _, err := os.Stat(serverDir); err != nil {
		add(".", reasonMissing, "服务器目录不存在", false)
		return
	}
	scan(serverDir)
	if jars() == 0 && findingsLen() == 0 {
		add(".", reasonMissing, emptyHint, false)
	}
}

func AuditModJarManifests(serverDir string) *ModJarManifestAudit {
	a := &ModJarManifestAudit{ServerDir: serverDir}
	runJarRootAudit(serverDir, mjmReasonMissing, mjmReasonSymlink, "未发现 mods 目录或 JAR",
		func(file, reason, detail string, blocking bool) { a.add(file, reason, detail, blocking) },
		func(dir string) { mjmScanDir(a, dir) },
		func() int { return a.Jars },
		func() int { return len(a.Findings) })
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
