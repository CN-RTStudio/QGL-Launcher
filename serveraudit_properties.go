package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	sprMaxFindings       = 48
	sprMaxProps          = 256 * 1024
	sprMaxViewDistance   = 16
	sprMinViewDistance   = 3
	sprMaxCompression    = 1024
	sprReasonOK          = "ok"
	sprReasonMissing     = "missing"
	sprReasonSymlink     = "symlink"
	sprReasonTooLarge    = "too-large"
	sprReasonUnreadable  = "unreadable"
	sprReasonBadConfig   = "bad-config"
	sprReasonBadValue    = "bad-value"
	sprReasonDupKey      = "duplicate-key"
	sprReasonViewLarge   = "view-distance-large"
	sprReasonViewSmall   = "view-distance-small"
	sprReasonSimDistance = "simulation-exceeds-view"
	sprReasonCompression = "compression-threshold"
	sprReasonWatchdog    = "watchdog-disabled"
	sprReasonPortClash   = "port-conflict"
	sprReasonLevelName   = "level-name-traversal"
	sprReasonPackURL     = "insecure-resource-pack"
)

type PropertiesBudgetFinding = auditFinding
type PropertiesBudgetAudit struct {
	ServerDir string
	Keys      int
	Findings  []PropertiesBudgetFinding
}

func (a *PropertiesBudgetAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sprMaxFindings, PropertiesBudgetFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *PropertiesBudgetAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PropertiesBudgetFinding) bool { return f.Blocking })
}
func (a *PropertiesBudgetAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PropertiesBudgetFinding) bool { return f.Reason != sprReasonOK && !f.Blocking })
}

func (a *PropertiesBudgetAudit) Describe() string {
	return describeFindings(a.Findings, func(f PropertiesBudgetFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

type sprProperties struct {
	Values     map[string]string
	Duplicates []string
	LongLines  int
}

func sprParseProperties(text string) sprProperties {
	out := sprProperties{Values: map[string]string{}}
	seen := map[string]bool{}
	text = strings.TrimPrefix(text, "\ufeff")
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		if len(line) > 4096 {
			out.LongLines++
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		if key == "" {
			continue
		}
		value := strings.TrimSpace(line[idx+1:])
		if seen[key] {
			out.Duplicates = append(out.Duplicates, key)
			continue
		}
		seen[key] = true
		out.Values[key] = value
	}
	return out
}

func sprCheckCompression(a *PropertiesBudgetAudit, props sprProperties) {
	value, ok := props.Values["network-compression-threshold"]
	if !ok {
		return
	}
	n, valid := cfgParseInt(value)
	if !valid {
		a.add("server.properties", sprReasonBadValue, "network-compression-threshold 不是合法整数: "+value, false)
		return
	}
	if n < -1 || n > sprMaxCompression {
		a.add("server.properties", sprReasonCompression, fmt.Sprintf("network-compression-threshold=%d 超出 -1..%d", n, sprMaxCompression), false)
	}
}
func sprCheckWatchdog(a *PropertiesBudgetAudit, props sprProperties) {
	value, ok := props.Values["max-tick-time"]
	if !ok {
		return
	}
	n, valid := cfgParseInt(value)
	if !valid {
		a.add("server.properties", sprReasonBadValue, "max-tick-time 不是合法整数: "+value, false)
		return
	}
	if n < 0 {
		a.add("server.properties", sprReasonWatchdog, fmt.Sprintf("max-tick-time=%d 关闭了卡顿看门狗", n), true)
	} else if n == 0 {
		a.add("server.properties", sprReasonWatchdog, "max-tick-time=0 关闭了卡顿看门狗", true)
	} else if n < 30000 {
		a.add("server.properties", sprReasonBadValue, fmt.Sprintf("max-tick-time=%d 毫秒过于敏感", n), false)
	}
}

func sprCheckPorts(a *PropertiesBudgetAudit, props sprProperties) {
	ports := map[string]int{}
	for _, key := range []string{"server-port", "query.port", "rcon.port"} {
		n, ok := sprCheckInt(a, props, key)
		if !ok {
			continue
		}
		if n < 1 || n > 65535 {
			a.add("server.properties", sprReasonBadValue, fmt.Sprintf("%s=%d 超出端口范围", key, n), false)
			continue
		}
		ports[key] = n
	}
	if serverPort, ok := ports["server-port"]; ok {
		for _, key := range []string{"query.port", "rcon.port"} {
			if n, exists := ports[key]; exists && n == serverPort {
				a.add("server.properties", sprReasonPortClash, fmt.Sprintf("%s 与 server-port 同为 %d", key, n), false)
			}
		}
	}
}

func sprCheckLevelName(a *PropertiesBudgetAudit, props sprProperties) {
	value, ok := props.Values["level-name"]
	if !ok {
		return
	}
	if value == "" {
		a.add("server.properties", sprReasonBadValue, "level-name 为空", false)
		return
	}
	if cfgHasControlChars(value) {
		a.add("server.properties", sprReasonBadValue, "level-name 含控制字符", true)
		return
	}
	if strings.Contains(value, "..") || strings.Contains(value, "/") || strings.Contains(value, "\\") || strings.HasPrefix(value, ".") {
		a.add("server.properties", sprReasonLevelName, "level-name 含路径穿越写法: "+value, true)
		return
	}
	if len(value) > 128 {
		a.add("server.properties", sprReasonBadValue, "level-name 过长", false)
	}
	if strings.ContainsAny(value, ":*?\"<>|") {
		a.add("server.properties", sprReasonBadValue, "level-name 含非法字符: "+value, false)
	}
}

func sprCheckResourcePack(a *PropertiesBudgetAudit, props sprProperties) {
	value, ok := props.Values["resource-pack"]
	if !ok || strings.TrimSpace(value) == "" {
		return
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") {
		a.add("server.properties", sprReasonPackURL, "resource-pack 使用明文 HTTP", false)
	} else if !strings.HasPrefix(lower, "https://") {
		a.add("server.properties", sprReasonPackURL, "resource-pack 不是 HTTPS 地址", false)
	}
	if cfgHasControlChars(value) || strings.Contains(value, "\n") {
		a.add("server.properties", sprReasonBadValue, "resource-pack 含换行或控制字符", true)
	}
	if value, ok := props.Values["resource-pack-sha1"]; ok && strings.TrimSpace(value) == "" {
		a.add("server.properties", sprReasonPackURL, "resource-pack-sha1 为空，客户端无法校验资源包", false)
	}
}

func sprCheckDuplicates(a *PropertiesBudgetAudit, props sprProperties) {
	if len(props.Duplicates) == 0 {
		return
	}
	seen := map[string]bool{}
	items := make([]string, 0, len(props.Duplicates))
	for _, key := range props.Duplicates {
		if seen[key] {
			continue
		}
		seen[key] = true
		items = append(items, key)
	}
	sort.Strings(items)
	if len(items) > 8 {
		items = items[:8]
	}
	a.add("server.properties", sprReasonDupKey, "重复键: "+strings.Join(items, ","), false)
}

func AuditServerPropertiesBudget(serverDir string) *PropertiesBudgetAudit {
	a := &PropertiesBudgetAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", sprReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sprReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", sprReasonMissing, "服务器目录不存在", false)
		return a
	}
	path := filepath.Join(serverDir, "server.properties")
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add("server.properties", sprReasonSymlink, "配置文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, sprMaxProps)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			a.add(".", sprReasonMissing, "未发现 server.properties", false)
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add("server.properties", sprReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", sprMaxProps), true)
			return a
		}
		a.add("server.properties", sprReasonUnreadable, "配置文件不可读", false)
		return a
	}
	props := sprParseProperties(string(data))
	a.Keys = len(props.Values)
	if a.Keys == 0 && strings.TrimSpace(string(data)) != "" {
		a.add("server.properties", sprReasonBadConfig, "未解析出任何键值", false)
		return a
	}
	if props.LongLines > 0 {
		a.add("server.properties", sprReasonBadConfig, fmt.Sprintf("存在 %d 行超长键值", props.LongLines), false)
	}
	sprCheckViewDistance(a, props)
	sprCheckCompression(a, props)
	sprCheckWatchdog(a, props)
	sprCheckPorts(a, props)
	sprCheckLevelName(a, props)
	sprCheckResourcePack(a, props)
	sprCheckDuplicates(a, props)
	if a.Keys == 0 {
		a.add(".", sprReasonMissing, "server.properties 为空", false)
	}
	return a
}

func sprCheckInt(a *PropertiesBudgetAudit, props sprProperties, key string) (int, bool) {
	value, ok := props.Values[key]
	if !ok {
		return 0, false
	}
	n, valid := cfgParseInt(value)
	if !valid {
		a.add("server.properties", sprReasonBadValue, key+" 不是合法整数: "+value, false)
		return 0, false
	}
	return n, true
}

func sprCheckViewDistance(a *PropertiesBudgetAudit, props sprProperties) {
	view, hasView := sprCheckInt(a, props, "view-distance")
	simulation, hasSimulation := sprCheckInt(a, props, "simulation-distance")
	if hasView {
		if view > sprMaxViewDistance {
			a.add("server.properties", sprReasonViewLarge, fmt.Sprintf("view-distance=%d 超过 %d，区块与实体负载放大", view, sprMaxViewDistance), false)
		}
		if view < sprMinViewDistance {
			a.add("server.properties", sprReasonViewSmall, fmt.Sprintf("view-distance=%d 低于 %d", view, sprMinViewDistance), false)
		}
	}
	if hasSimulation && hasView && simulation > view {
		a.add("server.properties", sprReasonSimDistance, fmt.Sprintf("simulation-distance=%d 大于 view-distance=%d", simulation, view), false)
	}
}

const (
	setbMaxFindings = 24
	setbMaxFile     = 512 * 1024
	setbMaxLine     = 512
	setbReasonMiss  = "missing"
	setbReasonLink  = "symlink"
	setbReasonLarge = "too-large"
	setbReasonRead  = "unreadable"
	setbReasonBOM   = "utf8-bom"
	setbReasonUTF8  = "invalid-utf8"
	setbReasonCRLF  = "crlf-endings"
	setbReasonNUL   = "nul-byte"
	setbReasonDup   = "duplicate-key"
	setbReasonKey   = "invalid-key"
	setbReasonLong  = "long-line"
	setbReasonEsc   = "bad-escape"
)

type PropertiesEncodingFinding = auditFinding
type PropertiesEncodingAudit struct {
	ServerDir string
	Findings  []PropertiesEncodingFinding
}

func (a *PropertiesEncodingAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, setbMaxFindings, PropertiesEncodingFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PropertiesEncodingAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PropertiesEncodingFinding) bool { return f.Blocking })
}

func (a *PropertiesEncodingAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PropertiesEncodingAudit) Describe() string {
	return describeReasonDetail("server.properties 编码未发现风险", a.Findings, 12)
}

func setbValidKey(key string) bool {
	if key == "" || len(key) > 64 {
		return false
	}
	for _, r := range key {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

func AuditServerPropertiesEncoding(serverDir string) *PropertiesEncodingAudit {
	a := &PropertiesEncodingAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("server.properties", setbReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "server.properties"
	path := filepath.Join(serverDir, rel)
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, setbReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, setbReasonLink, "属性文件是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, setbReasonMiss, "未找到 server.properties", false)
		return a
	}
	data, err := readBoundedFile(path, setbMaxFile)
	if err != nil {
		reason := setbReasonRead
		if err == errLocalFileTooLarge {
			reason = setbReasonLarge
		}
		a.add(rel, reason, err.Error(), true)
		return a
	}
	if len(data) > 0 && data[0] == 0xEF {
		if len(data) >= 3 && data[1] == 0xBB && data[2] == 0xBF {
			a.add(rel, setbReasonBOM, "文件带 UTF-8 BOM", true)
		}
	}
	if strings.Contains(string(data), "\x00") {
		a.add(rel, setbReasonNUL, "文件含 NUL 字节", true)
	}
	if !utf8.Valid(data) {
		a.add(rel, setbReasonUTF8, "文件不是合法 UTF-8", true)
	}
	text := string(data)
	if strings.Contains(text, "\r\n") {
		a.add(rel, setbReasonCRLF, "使用 CRLF 换行", false)
	}
	keys := map[string]int{}
	for idx, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if len(raw) > setbMaxLine {
			a.add(rel, setbReasonLong, "第 "+strconv.Itoa(idx+1)+" 行过长", false)
			continue
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		eq := strings.IndexAny(line, "=:")
		if eq <= 0 {
			a.add(rel, setbReasonKey, "第 "+strconv.Itoa(idx+1)+" 行缺少键值分隔", false)
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if !setbValidKey(key) {
			a.add(rel, setbReasonKey, "第 "+strconv.Itoa(idx+1)+" 行键非法", true)
			continue
		}
		keys[key]++
		if keys[key] > 1 {
			a.add(rel, setbReasonDup, key+" 重复定义", false)
		}
		value := line[eq+1:]
		if strings.Contains(value, "\\") && strings.Count(value, "\\")%2 == 1 {
			a.add(rel, setbReasonEsc, key+" 转义不完整", false)
		}
	}
	return a
}

const (
	spxMaxFindings = 18
	spxMaxFile     = 256 * 1024
	spxMaxKeys     = 512
	spxMaxDetail   = 8
	spxMiss        = "properties-missing"
	spxRead        = "properties-unreadable"
	spxLink        = "properties-symlink"
	spxEmpty       = "properties-empty"
	spxMalformed   = "properties-line-malformed"
	spxDupKey      = "properties-duplicate-key"
	spxCaseDup     = "properties-case-duplicate"
	spxEmptyKey    = "properties-empty-key"
	spxKeySpace    = "properties-key-whitespace"
	spxInlineHash  = "properties-inline-comment"
	spxTooManyKeys = "properties-key-count"
	spxLongValue   = "properties-value-too-long"
)

type PropDupFinding = auditFinding
type PropDupAudit struct {
	ServerDir string
	Findings  []PropDupFinding
}

func (a *PropDupAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spxMaxFindings, PropDupFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PropDupAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PropDupFinding) bool { return f.Blocking })
}

func (a *PropDupAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PropDupAudit) Describe() string {
	return describeReasonDetail("属性文件键结构未发现重复或畸形", a.Findings, 12)
}

func spxEntry(index int, key, value string) string {
	if len(value) > 40 {
		value = value[:40] + "…"
	}
	return fmt.Sprintf("第 %d 行 %s=%s", index, key, value)
}

func AuditServerPropertiesStructure(serverDir string) *PropDupAudit {
	a := &PropDupAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(spxMiss, "未配置服务器目录", false)
		return a
	}
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(spxMiss, "缺少 server.properties", false)
		return a
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(spxRead, err.Error(), true)
		return a
	}
	if link {
		a.add(spxLink, "属性文件是符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, spxMaxFile)
	if err != nil {
		a.add(spxRead, err.Error(), true)
		return a
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	lines := strings.Split(text, "\n")
	firstSeen := map[string]int{}
	foldedSeen := map[string]string{}
	keys := 0
	for i, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		index := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			a.add(spxMalformed, fmt.Sprintf("第 %d 行缺少等号，整行被忽略", index), false)
			continue
		}
		key := line[:eq]
		value := line[eq+1:]
		keys++
		if key == "" {
			a.add(spxEmptyKey, fmt.Sprintf("第 %d 行的键为空", index), true)
			continue
		}
		if strings.TrimSpace(key) != key {
			a.add(spxKeySpace, fmt.Sprintf("第 %d 行的键带首尾空白", index), false)
		}
		if len(value) > 2048 {
			a.add(spxLongValue, fmt.Sprintf("第 %d 行的值长度 %d 异常", index, len(value)), false)
		}
		if strings.Contains(value, "#") && !strings.HasPrefix(strings.TrimSpace(value), "#") {
			a.add(spxInlineHash, fmt.Sprintf("第 %d 行的值含 #，不是注释而是字面内容", index), false)
		}
		if prev, ok := firstSeen[key]; ok {
			a.add(spxDupKey, fmt.Sprintf("%s 与第 %d 行重复", spxEntry(index, key, value), prev), true)
		} else {
			firstSeen[key] = index
		}
		folded := strings.ToLower(key)
		if prev, ok := foldedSeen[folded]; ok && prev != key {
			a.add(spxCaseDup, fmt.Sprintf("第 %d 行 %s 与 %s 仅大小写不同", index, key, prev), true)
		} else if !ok {
			foldedSeen[folded] = key
		}
	}
	if keys == 0 {
		a.add(spxEmpty, "属性文件没有任何有效键值", false)
	}
	if keys > spxMaxKeys {
		a.add(spxTooManyKeys, fmt.Sprintf("键数量 %d 超出上限 %d", keys, spxMaxKeys), false)
	}
	return a
}
