package main

// forgeguard.go —— Forge / NeoForge 加载器版本字符串与下载地址校验内核。
//
// 背景：
//   Forge 安装链路是 "版本清单 JSON -> files.minecraftforge.net / maven 构件"，
//   版本标识来自远端清单与用户输入。攻击面与 fabricguard 平行但格式不同：
//     1) Forge 版本串形态多样：独立版本（"47.1.0"）、组合版本
//        （"1.20.1-forge-47.1.0"、"47.1.0-1.20.1"）、NeoForge（"20.4.80-beta"），
//        若不作结构校验，恶意清单可在版本串里塞路径分隔符/控制字符/超长段，
//        拼进下载 URL 或本地目录名后越界写文件；
//     2) 下载地址投毒：镜像/中间人把 files.minecraftforge.net 换成别的 host，
//        启动器从不可信来源拉构件（供应链起点污染）；
//     3) 版本选择陷阱：Forge 版本号是纯数字点段（47.1.0），字典序比较在
//        "47.10.0" < "47.9.0" 上会选错版本。
//   本模块对版本串结构、下载 URL、maven 路径段三处收口；数字段比较与
//   fabricguard.CompareFabricVersions 同源。
//
// 注意：Forge 版本允许的字母段（forge/neoforge 与预发布后缀）有明确白名单，
// 其余段必须为纯数字点段——这既防注入也防 "latest"/"recommended" 之类
// 非固定标识被当作下载路径段。

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// ForgeLimits 限定 Forge 版本与 URL 的输入边界。
type ForgeLimits struct {
	MaxVersionRunes  int
	MaxUrlRunes      int
	MaxPathSegments  int
	MaxSegmentRunes  int
}

func (l *ForgeLimits) withDefaults() ForgeLimits {
	if l == nil {
		l = &ForgeLimits{}
	}
	out := *l
	if out.MaxVersionRunes <= 0 {
		out.MaxVersionRunes = 96
	}
	if out.MaxUrlRunes <= 0 {
		out.MaxUrlRunes = 2048
	}
	if out.MaxPathSegments <= 0 {
		out.MaxPathSegments = 12
	}
	if out.MaxSegmentRunes <= 0 {
		out.MaxSegmentRunes = 160
	}
	return out
}

// forgeAllowedTokens 是版本串中允许出现的非数字标识（大小写不敏感）。
// 组合版本里 MC 侧版本（1.20.1）与加载器标识（forge/neoforge）都归到这里；
// 其余字母一律拒绝。
var forgeAllowedTokens = map[string]bool{
	"forge": true, "neoforge": true, "fml": true, "mcp": true,
	"alpha": true, "beta": true, "rc": true, "pre": true, "snapshot": true,
}

// splitForgeVersion 把组合版本拆成段；返回主版本串与错误。
// 支持形态：
//   "47.1.0"
//   "1.20.1-forge-47.1.0"
//   "47.1.0-1.20.1"
//   "20.4.80-beta"
//   "1.20.1-neoforge-20.4.80"
func splitForgeVersion(raw string) (string, error) {
	if strings.ContainsAny(raw, `/\`) {
		return "", errors.New("forge version must not contain path separators")
	}
	// 逐段过白名单：数字点段直接通过，字母段必须是 forgeAllowedTokens。
	// 把字母段剥离后剩余的纯数字点段即为规范版本主体。
	for _, seg := range strings.Split(raw, "-") {
		if seg == "" {
			return "", errors.New("forge version has empty segment")
		}
		lower := strings.ToLower(seg)
		if forgeAllowedTokens[lower] {
			continue
		}
		// 数字点段：每段非空且全数字（允许前导零，如 "1.20.1"）。
		parts := strings.Split(seg, ".")
		for _, p := range parts {
			if p == "" {
				return "", errors.New("forge version segment has empty part")
			}
			for _, r := range p {
				if (r < '0' || r > '9') && r != '_' {
					return "", errors.New("forge version segment has non-digit part: " + seg)
				}
			}
		}
	}
	// 主体取第一个纯数字点段（组合形态里 MC 版本在最前或最后，任意一个数字
	// 点段都能独立构成规范版本；这里返回去掉字母段后的规范化串）。
	var nums []string
	for _, seg := range strings.Split(raw, "-") {
		lower := strings.ToLower(seg)
		if forgeAllowedTokens[lower] {
			continue
		}
		nums = append(nums, seg)
	}
	if len(nums) == 0 {
		return "", errors.New("forge version has no numeric component")
	}
	return strings.Join(nums, "-"), nil
}

// ValidateForgeVersionString 校验 Forge/NeoForge 版本字符串并返回规范化主体。
func ValidateForgeVersionString(v string, lim ForgeLimits) (string, error) {
	d := lim.withDefaults()
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return "", errors.New("forge version is empty")
	}
	if len([]rune(trimmed)) > d.MaxVersionRunes {
		return "", errors.New("forge version too long")
	}
	if hasControlCharStr(trimmed) {
		return "", errors.New("forge version contains control characters")
	}
	normalized, err := splitForgeVersion(trimmed)
	if err != nil {
		return "", err
	}
	return normalized, nil
}

// CompareForgeVersions 比较两个规范 Forge 版本（数字点段，逐段数值比较）。
// 返回 -1/0/1；预发布后缀（beta/rc/pre+数字）视为小于同号正式版。
// 解决 "47.10.0" 与 "47.9.0" 的字典序陷阱。
func CompareForgeVersions(a, b string) int {
	an, as := numericAndSuffix(a)
	bn, bs := numericAndSuffix(b)
	if c := compareNumericSegs(an, bn); c != 0 {
		return c
	}
	// 同为正式版或同为预发布且编号相同 => 相等；预发布恒小于正式版。
	if as == "" && bs == "" {
		return 0
	}
	if as == "" {
		return 1
	}
	if bs == "" {
		return -1
	}
	return compareSuffixes(as, bs)
}

func numericAndSuffix(v string) (string, string) {
	if i := strings.LastIndexByte(v, '-'); i > 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func compareNumericSegs(a, b string) int {
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(ap) {
			av, _ = strconv.Atoi(ap[i])
		}
		if i < len(bp) {
			bv, _ = strconv.Atoi(bp[i])
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

// suffixRank 给预发布后缀排优先级，越小越"前"（更早/更不稳定）。
var suffixRank = map[string]int{
	"alpha": 1, "beta": 2, "pre": 3, "rc": 4, "snapshot": 2,
}

func compareSuffixes(a, b string) int {
	an, anum := splitSuffix(a)
	bn, bnum := splitSuffix(b)
	ar, aok := suffixRank[an]
	br, bok := suffixRank[bn]
	if aok && bok && ar != br {
		if ar < br {
			return -1
		}
		return 1
	}
	if anum != bnum {
		if anum < bnum {
			return -1
		}
		return 1
	}
	if !aok && bok {
		return 1
	}
	if aok && !bok {
		return -1
	}
	return 0
}

// splitSuffix 拆 "beta3" -> ("beta", 3)；无编号时返回 0。
func splitSuffix(s string) (string, int) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	name := strings.ToLower(s[:i])
	num, _ := strconv.Atoi(s[i:])
	return name, num
}

// forgeDownloadHosts 是允许作为 Forge/NeoForge 构件来源的官方主机。
var forgeDownloadHosts = []string{
	"files.minecraftforge.net",
	"maven.minecraftforge.net",
	"maven.neoforged.net",
	"maven.fabricmc.net", // 部分 Forge 依赖（如 bundler 拆包用 fabric 的 maven）不涉及
	"raw.githubusercontent.com",
}

// ValidateForgeDownloadURL 校验 Forge 下载 URL：https + 白名单 host（精确或
// 子域，禁止 IP）+ 路径段数与段长上限。
func ValidateForgeDownloadURL(raw string, lim ForgeLimits) (string, error) {
	d := lim.withDefaults()
	if len([]rune(raw)) > d.MaxUrlRunes {
		return "", errors.New("forge download url too long")
	}
	if hasControlCharStr(raw) {
		return "", errors.New("forge download url contains control characters")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("forge download url is not parseable")
	}
	if u.Scheme != "https" {
		return "", errors.New("forge download url must use https")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("forge download url has no host")
	}
	// 禁止 IP 直连（白名单主机必须是域名）。
	if isIPLiteralHost(host) {
		return "", errors.New("forge download url must not use ip address")
	}
	if !hostAllowed(host, forgeDownloadHosts) {
		return "", errors.New("forge download host not allowed: " + host)
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) > d.MaxPathSegments {
		return "", errors.New("forge download url has too many path segments")
	}
	for _, s := range segs {
		if s == "" {
			continue
		}
		if len([]rune(s)) > d.MaxSegmentRunes {
			return "", errors.New("forge download url has overlong path segment")
		}
	}
	if u.User != nil {
		return "", errors.New("forge download url must not contain userinfo")
	}
	return u.String(), nil
}

// hostAllowed 判断 host 是否等于白名单项或为其子域（label 边界匹配）。
// 定义在 updateguard.go，本模块复用。

// ForgeVerdict 描述一条 Forge 安装输入的校验结论。
type ForgeVerdict struct {
	NormalizedVersion string
	DownloadURL       string
	OK                bool
	Reason            string
}

// SummarizeForgeVerdict 把结论压成一行可审计文本。
func SummarizeForgeVerdict(v ForgeVerdict) string {
	if v.OK {
		return "forge install ok version=" + v.NormalizedVersion + " url=" + v.DownloadURL
	}
	return "forge install rejected reason=" + v.Reason
}
