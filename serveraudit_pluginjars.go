package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
