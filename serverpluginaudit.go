package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

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
