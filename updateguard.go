package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
)

// updateguard.go —— 启动器自更新包校验内核。
//
// 自更新是 MC 启动器最常被利用的供应链攻击面：若更新包下载 URL / 版本比较 /
// 包内结构不做校验，攻击者可以做三件事：
//
//  1. 版本回滚降级：把"版本比较"实现成字符串字典序（"9.9" > "9.10" 的经典
//     错误），或接受一个比当前更旧的版本号，诱使启动器"升级"到带漏洞的旧版；
//  2. MITM / 换源投毒：更新 URL 允许 http、IP 直连、带用户信息，或域名不受
//     约束，中间人可直接换包；
//  3. 包内结构攻击：更新包 zip 里藏 ../ 路径穿越 / 符号链接 / 超量条目，
//     解压时覆盖启动器目录之外的文件。
//
// 本内核只做纯校验，不执行下载与解压；调用方按 verdict 决定是否安装。
// 对外部厂商哈希（Mojang/authlib/Modrinth）的校验不在本文件——本文件只管
// 自更新渠道自身的版本 / URL / 包结构安全。

const (
	maxUpdateUrlLen       = 2048              // URL 长度上限
	maxUpdateAssetNameLen = 256               // 发布资产文件名上限
	maxUpdateZipBytes     = 512 * 1024 * 1024 // 更新包总量上限
	maxUpdateZipEntries   = 20000             // 更新包条目上限
	maxUpdateVersionParts = 32                // 版本号拆段上限
	maxUpdateDescRunes    = 2048              // 更新说明长度上限
)

// allowedUpdateHosts 是默认允许的更新源域名白名单（不含协议与路径）。
// 域名匹配采用"精确或子域"规则，杜绝前缀误配（evil-update.example.com 不算
// example.com 的子域）。
var allowedUpdateHosts = []string{
	"api.github.com",
	"github.com",
	"objects.githubusercontent.com",
	"raw.githubusercontent.com",
	"codeload.github.com",
	"release-assets.githubusercontent.com",
}

// UpdateLimits 是调用方可覆写的限额；零值字段使用默认值。
type UpdateLimits struct {
	UrlLenMax     int
	AssetNameLen  int
	ZipBytesMax   int64
	ZipEntriesMax int
	VersionParts  int
	DescRunesMax  int
}

func (l UpdateLimits) withDefaults() UpdateLimits {
	if l.UrlLenMax <= 0 {
		l.UrlLenMax = maxUpdateUrlLen
	}
	if l.AssetNameLen <= 0 {
		l.AssetNameLen = maxUpdateAssetNameLen
	}
	if l.ZipBytesMax <= 0 {
		l.ZipBytesMax = maxUpdateZipBytes
	}
	if l.ZipEntriesMax <= 0 {
		l.ZipEntriesMax = maxUpdateZipEntries
	}
	if l.VersionParts <= 0 {
		l.VersionParts = maxUpdateVersionParts
	}
	if l.DescRunesMax <= 0 {
		l.DescRunesMax = maxUpdateDescRunes
	}
	return l
}

// UpdateFindings 是校验结论的条目；Severity 用于 UI 分级（error/warn/info）。
type UpdateFindings struct {
	Severity string // "error" / "warn" / "info"
	Code     string
	Message  string
}

// UpdateVerdict 是一次校验的完整结论。
type UpdateVerdict struct {
	OK             bool
	Findings       []UpdateFindings
	Version        string
	VersionValid   bool
	AssetName      string
	HasSingleRoot  bool
	HasLauncherExe bool
	ZipEntryCount  int
	ZipTotalBytes  int64
}

// sanitizeUpdateUrl 校验更新包下载地址：
//   - 必须 https；
//   - 长度受限；
//   - 不允许嵌入用户信息（user:pass@）；
//   - host 必须命中白名单（精确或子域）；
//   - 不允许把 IP 文字形式当 host（IP 直连的更新源无法做域名级信任）。
//
// 返回 {ok, host, reason}。
func sanitizeUpdateUrl(raw string, limits UpdateLimits) (bool, string, string) {
	l := limits.withDefaults()
	if len(raw) > l.UrlLenMax {
		return false, "", "更新 URL 超过长度上限"
	}
	if !strings.HasPrefix(raw, "https://") {
		return false, "", "更新 URL 必须使用 HTTPS"
	}
	rest := raw[len("https://"):]
	if at := strings.Index(rest, "@"); at >= 0 {
		return false, "", "更新 URL 不允许携带用户信息"
	}
	slash := strings.IndexAny(rest, "/?#")
	var hostPort string
	if slash < 0 {
		hostPort = rest
	} else {
		hostPort = rest[:slash]
	}
	host := hostPort
	if idx := strings.LastIndex(hostPort, ":"); idx > 0 && strings.IndexByte(hostPort[idx+1:], ':') < 0 {
		host = hostPort[:idx]
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return false, "", "更新 URL 缺少主机名"
	}
	// IP 文字形式（IPv4 / IPv6）一律拒绝：更新源必须可审计的域名。
	if isIPLiteralHost(host) {
		return false, "", "更新 URL 不允许 IP 直连"
	}
	if !hostAllowed(host, allowedUpdateHosts) {
		return false, "", "更新源域名不在白名单内"
	}
	return true, host, ""
}

// isIPLiteralHost 报告 host 是否是 IP 字面量（IPv6 含冒号即算；IPv4 走宽解析器）。
// 收敛到 parseDestIP：旧实现只认严格四段十进制，单整数 2130706433、
// 十六进制 0x7f000001、八进制 0177.0.0.1、短格式 127.1 都会漏过"拒绝裸 IP"这道门，
// 被误当成域名。更新源 / Forge 镜像 / 服务器列表三处调用方一同受益。
func isIPLiteralHost(host string) bool {
	if strings.Contains(host, ":") {
		return true
	}
	_, ok := parseDestIP(host)
	return ok
}

// hostAllowed 判断 host 是否等于白名单项或为其子域（label 边界匹配）。
func hostAllowed(host string, allow []string) bool {
	for _, a := range allow {
		a = strings.ToLower(a)
		if host == a {
			return true
		}
		if strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

// sanitizeUpdateAssetName 校验发布资产文件名：不得为空、超长、含路径分隔与
// 控制字符。assetName 只允许是一个"文件名"，任何路径形状（含 / \ ..）都拒绝。
func sanitizeUpdateAssetName(name string, limits UpdateLimits) (string, bool) {
	l := limits.withDefaults()
	if name == "" || len(name) > l.AssetNameLen {
		return "", false
	}
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return "", false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return name, true
}

// ParseVersionParts 把版本号拆成可比较的 token 序列（数字段按数值、非数字段
// 按 rune 序，数字 token 排在字母 token 之前）。"9.9" 与 "9.10" 由此正确比较。
// 返回 nil 表示版本号非法（空 / 超长 / 含控制字符）。
func ParseVersionParts(v string, limits UpdateLimits) [][]string {
	l := limits.withDefaults()
	if v == "" || len(v) > l.UrlLenMax/2 {
		return nil
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return nil
		}
	}
	raw := strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+'
	})
	if len(raw) == 0 || len(raw) > l.VersionParts {
		return nil
	}
	parts := make([][]string, 0, len(raw))
	for _, tok := range raw {
		if tok == "" {
			return nil
		}
		parts = append(parts, []string{tok})
	}
	return parts
}

// CompareVersionTokens 比较两个已拆好的版本 token 序列。
// 返回值 <0 / 0 / >0 对应 a<b / a==b / a>b。
// 规则：数字 token 数值比较（'9' < '10'）；字母 token 按 rune 字典序；
// 数字 token 整体小于字母 token；段数不同时缺段视为 0（数字）或空（字母）。
func CompareVersionTokens(a, b [][]string) int {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		var av, bv string
		if i < len(a) {
			av = a[i][0]
		}
		if i < len(b) {
			bv = b[i][0]
		}
		if av == bv {
			continue
		}
		aNum, aIsNum := numericToken(av)
		bNum, bIsNum := numericToken(bv)
		switch {
		case aIsNum && bIsNum:
			if aNum < bNum {
				return -1
			}
			if aNum > bNum {
				return 1
			}
		case aIsNum != bIsNum:
			if aIsNum {
				return -1
			}
			return 1
		default:
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func numericToken(s string) (int64, bool) {
	if s == "" {
		return 0, true // 缺段视为数字 0
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// IsVersionNewer 判断候选版本是否比当前版本"更新"（语义比较）。
func IsVersionNewer(candidate, current string, limits UpdateLimits) (bool, error) {
	c := ParseVersionParts(candidate, limits)
	cur := ParseVersionParts(current, limits)
	if c == nil || cur == nil {
		return false, errors.New("版本号格式非法")
	}
	return CompareVersionTokens(c, cur) > 0, nil
}

// sanitizeUpdateDesc 校验更新说明：限长、拒绝控制字符。
func sanitizeUpdateDesc(desc string, limits UpdateLimits) (string, bool) {
	l := limits.withDefaults()
	if desc == "" {
		return desc, true
	}
	if len([]rune(desc)) > l.DescRunesMax {
		return "", false
	}
	for _, r := range desc {
		if r < 0x20 && r != '\n' && r != '\t' {
			return "", false
		}
	}
	return desc, true
}

// InspectUpdateZip 只读预检更新包 zip：条目路径全部过 secureZipRelPath；
// 拒绝符号链接 / 设备条目；条目数与总大小设上限；记录是否存在单一顶层目录
// 与启动器可执行入口（*.exe / 二进制根文件）。不落盘任何内容。
func InspectUpdateZip(zr *zip.Reader, limits UpdateLimits) UpdateVerdict {
	l := limits.withDefaults()
	v := UpdateVerdict{OK: true, Findings: []UpdateFindings{}}
	seen := map[string]bool{}
	var rootDirs []string
	hasExe := false
	rootEntries := 0

	for _, f := range zr.File {
		v.ZipEntryCount++
		if v.ZipEntryCount > l.ZipEntriesMax {
			v.OK = false
			v.Findings = append(v.Findings, UpdateFindings{"error", "zip-entries-overflow",
				fmt.Sprintf("更新包条目数超过上限 %d", l.ZipEntriesMax)})
			return v
		}
		if f.UncompressedSize64 > uint64(l.ZipBytesMax) {
			v.OK = false
			v.Findings = append(v.Findings, UpdateFindings{"error", "zip-entry-too-big",
				fmt.Sprintf("条目 %s 超过总量上限", f.Name)})
			return v
		}
		v.ZipTotalBytes += int64(f.UncompressedSize64)
		if v.ZipTotalBytes > l.ZipBytesMax {
			v.OK = false
			v.Findings = append(v.Findings, UpdateFindings{"error", "zip-total-overflow",
				"更新包解压后总大小超过上限"})
			return v
		}

		if f.Mode()&(osModeSymlink|osModeDevice) != 0 {
			v.OK = false
			v.Findings = append(v.Findings, UpdateFindings{"error", "zip-special-entry",
				fmt.Sprintf("更新包含符号链接/设备条目: %s", f.Name)})
			continue
		}

		rel, ok := secureZipRelPath(f.Name)
		if !ok {
			v.OK = false
			v.Findings = append(v.Findings, UpdateFindings{"error", "zip-unsafe-path",
				fmt.Sprintf("更新包含不安全路径条目: %s", f.Name)})
			continue
		}
		if seen[rel] {
			continue // 重复条目只审计一次
		}
		seen[rel] = true

		dir := path.Dir(rel)
		if dir == "." {
			rootEntries++
		} else {
			top := strings.Split(dir, "/")[0]
			rootDirs = append(rootDirs, top)
		}
		base := path.Base(rel)
		if strings.HasSuffix(strings.ToLower(base), ".exe") {
			hasExe = true
		}
	}

	// 单一顶层目录：正常更新包应把可执行文件等全部放在同一个顶层目录下，
	// 多个顶层目录提示打包错误或攻击者拼凑内容。
	uniqRoots := uniqueStrings(rootDirs)
	if len(uniqRoots) > 1 {
		v.OK = false
		v.Findings = append(v.Findings, UpdateFindings{"error", "zip-multi-root",
			fmt.Sprintf("更新包存在多个顶层目录: %s", strings.Join(uniqRoots, ", "))})
	} else if len(uniqRoots) == 1 {
		v.HasSingleRoot = true
	}
	v.HasLauncherExe = hasExe
	if !hasExe && rootEntries == 0 {
		v.OK = false
		v.Findings = append(v.Findings, UpdateFindings{"error", "zip-no-launcher",
			"更新包内未找到可执行入口"})
	}
	return v
}

// 常量表：文件模式位（对齐 io/fs 定义）。zip 条目来自外部属性，符号链接与
// 设备位按 fs.ModeSymlink / fs.ModeDevice 语义判定，命中任一即拒绝。
const (
	osModeSymlink = 1 << 27 // fs.ModeSymlink
	osModeDevice  = 1 << 26 // fs.ModeDevice
)

func uniqueStrings(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || m[s] {
			continue
		}
		m[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// SummarizeUpdateVerdict 把校验结论压成便于展示的纯文本（不参与判定）。
func SummarizeUpdateVerdict(v UpdateVerdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "OK=%v entries=%d bytes=%d singleRoot=%v launcherExe=%v",
		v.OK, v.ZipEntryCount, v.ZipTotalBytes, v.HasSingleRoot, v.HasLauncherExe)
	for _, f := range v.Findings {
		fmt.Fprintf(&b, " [%s:%s %s]", f.Severity, f.Code, f.Message)
	}
	return b.String()
}

// validateUpdateDescRune 用于描述串的 rune 级检查（与 sanitizeUpdateDesc 同源，
// 供单测直接断言边界）。
func validateUpdateDescRune(r rune) bool {
	return !(r < 0x20 && r != '\n' && r != '\t')
}

// hasControlCharStr 已在 modsaudit.go 定义，此处复用，不再重复声明。

// readZipEntryText 读取 zip 条目文本（有界），供校验器对更新说明 / 元数据做
// 二次检查时使用；超过上限直接失败，不放大内存。
func readZipEntryText(f *zip.File, maxBytes int64) (string, error) {
	if f.UncompressedSize64 > uint64(maxBytes) {
		return "", errors.New("条目超过读取上限")
	}
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	limited := io.LimitReader(rc, maxBytes+1)
	buf := make([]byte, 0, int(f.UncompressedSize64+1))
	tmp := make([]byte, 4096)
	for {
		n, err := limited.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if int64(len(buf)) > maxBytes {
			return "", errors.New("条目超过读取上限")
		}
	}
	// 控制字符检测（允许 \n \t）。
	for _, r := range string(buf) {
		if !validateUpdateDescRune(r) {
			return "", errors.New("条目含控制字符")
		}
	}
	return string(buf), nil
}

// 导出版本比较与 URL 校验的别名函数，供测试与调用方统一入口。
func ValidateUpdateUrl(raw string, limits UpdateLimits) (bool, string, string) {
	return sanitizeUpdateUrl(raw, limits)
}

func ValidateUpdateAssetName(name string, limits UpdateLimits) (string, bool) {
	return sanitizeUpdateAssetName(name, limits)
}
