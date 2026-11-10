package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

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
	runJarRootAudit(serverDir, mpeReasonMissing, mpeReasonSymlink, "未发现 plugins 目录或 JAR",
		func(file, reason, detail string, blocking bool) { a.add(file, reason, detail, blocking) },
		func(dir string) { mpeScanDir(a, dir) },
		func() int { return a.Jars },
		func() int { return len(a.Findings) })
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
