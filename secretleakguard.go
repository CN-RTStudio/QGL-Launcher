package main

// secretleakguard.go —— 文本中的密钥/凭据泄露扫描与脱敏守卫。
//
// 背景：
//   启动器会把调试信息、请求头、异常栈、配置、服务器返回写进日志或崩溃报告。其中容易混入：
//     - 微软/Mojang OAuth 访问令牌（JWT 形态 eyJ...）、刷新令牌；
//     - 第三方服务密钥：AWS AKIA/ASIA、GitHub ghp_/gho_/ghu_/ghs_/ghr_、Slack xox*、
//       Google AIza、Stripe sk_live_、私有 PEM 块；
//     - 显式键值对：password=/token=/secret=/api_key=（用户在自定义服务器/代理里填的）；
//     - Authorization: Bearer xxx 头。
//   一旦随崩溃报告/日志外发，即造成凭据泄露。本模块在落盘/上报前做纯字节扫描（不使用正则），
//   识别固定格式令牌与键值赋值，并给出可直接替换的脱敏文本。
//
//   本地用途的内容哈希沿用 UMFS；本模块只做"识别与打码"，不做哈希落盘。

import (
	"strings"
)

const (
	SLKReasonAWSAccessKey  = "slk-aws-access-key-id"
	SLKReasonGitHubToken   = "slk-github-token"
	SLKReasonSlackToken    = "slk-slack-token"
	SLKReasonGoogleAPIKey  = "slk-google-api-key"
	SLKReasonStripeLiveKey = "slk-stripe-live-key"
	SLKReasonPrivateKeyPEM = "slk-private-key-pem"
	SLKReasonJWT           = "slk-jwt-bearer-token"
	SLKReasonBearerHeader  = "slk-authorization-bearer"
	SLKReasonAssignment    = "slk-sensitive-assignment"
	SLKReasonHighEntropy   = "slk-high-entropy-run"
)

// SLKPolicy 控制检测项。
type SLKPolicy struct {
	MaxScanBytes       int  // 超长文本只扫前 N 字节，<=0 全文
	DetectKnownFormats bool // 固定格式令牌
	DetectAssignments  bool // password=/token= 等键值
	DetectHighEntropy  bool // 长串高熵
	EntropyMinLen      int  // 高熵判定最小长度
	EntropyMinDistinct int  // 最少不同字符数
	MaskRune           byte // 脱敏替换字符
}

// SLKFinding 记录一处疑似密钥。
type SLKFinding struct {
	Reason string
	Start  int
	End    int
	Token  string
}

// DefaultSLKPolicy 返回默认策略。
func DefaultSLKPolicy() SLKPolicy {
	return SLKPolicy{
		MaxScanBytes:       4 * 1024 * 1024,
		DetectKnownFormats: true,
		DetectAssignments:  true,
		DetectHighEntropy:  true,
		EntropyMinLen:      24,
		EntropyMinDistinct: 14,
		MaskRune:           '*',
	}
}

// slkLower ASCII 小写。
func slkLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// slkIsTokenChar 判断令牌字符（字母数字及常见令牌符号）。
func slkIsTokenChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_' || b == '-' || b == '.' || b == '~' || b == '+' || b == '/'
}

// slkTokenEnd 返回从 i 起连续令牌字符的结束下标。
func slkTokenEnd(s string, i int) int {
	for i < len(s) && slkIsTokenChar(s[i]) {
		i++
	}
	return i
}

// slkIsAllCaps 简单判断 AWS 风格：4 字母前缀 + 16 个大写字母/数字。
func slkAllCapsAlphaNum(s string) bool {
	if len(s) < 20 {
		return false
	}
	for i := 4; i < len(s); i++ {
		c := s[i]
		isUp := c >= 'A' && c <= 'Z'
		isDigit := c >= '0' && c <= '9'
		if !isUp && !isDigit {
			return false
		}
	}
	return true
}

// slkDistinct 统计不同字符数。
func slkDistinct(s string) int {
	seen := [256]bool{}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !seen[c] {
			seen[c] = true
			n++
		}
	}
	return n
}

// slkPrefixMatchAt 判断 s[at:] 是否以 lit 开头（大小写敏感，令牌前缀本身大小写固定）。
func slkPrefixAt(s string, at int, lit string) bool {
	return at+len(lit) <= len(s) && s[at:at+len(lit)] == lit
}

// slkKnownAt 从位置 i 识别固定格式令牌，返回结束下标与原因。
func slkKnownAt(s string, i int) (end int, reason string, ok bool) {
	// AWS Access Key：AKIA/ASIA/AGPA/AROA/AIDA + 16
	for _, pre := range []string{"AKIA", "ASIA", "AGPA", "AROA", "AIDA"} {
		if slkPrefixAt(s, i, pre) {
			e := slkTokenEnd(s, i)
			tok := s[i:e]
			if e-i == 20 && slkAllCapsAlphaNum(tok) {
				return e, SLKReasonAWSAccessKey, true
			}
		}
	}
	// GitHub
	for _, pre := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"} {
		if slkPrefixAt(s, i, pre) {
			e := slkTokenEnd(s, i)
			if e-i >= 30 {
				return e, SLKReasonGitHubToken, true
			}
		}
	}
	// Google API key
	if slkPrefixAt(s, i, "AIza") {
		e := slkTokenEnd(s, i)
		if e-i == 39 {
			return e, SLKReasonGoogleAPIKey, true
		}
	}
	// Stripe live
	if slkPrefixAt(s, i, "sk_live_") {
		e := slkTokenEnd(s, i)
		if e-i >= 24 {
			return e, SLKReasonStripeLiveKey, true
		}
	}
	// Slack xox[baprs]-
	if slkPrefixAt(s, i, "xox") && i+4 < len(s) {
		c4 := s[i+3]
		if (c4 == 'b' || c4 == 'a' || c4 == 'p' || c4 == 'r' || c4 == 's') && s[i+4] == '-' {
			e := slkTokenEnd(s, i)
			if e-i >= 12 {
				return e, SLKReasonSlackToken, true
			}
		}
	}
	return 0, "", false
}

// SLKInspect 扫描文本中的疑似密钥。
func SLKInspect(text string, policy SLKPolicy) (safe bool, findings []SLKFinding) {
	s := text
	if policy.MaxScanBytes > 0 && len(s) > policy.MaxScanBytes {
		s = s[:policy.MaxScanBytes]
	}

	if policy.DetectKnownFormats {
		i := 0
		for i < len(s) {
			end, reason, ok := slkKnownAt(s, i)
			if ok {
				findings = append(findings, SLKFinding{Reason: reason,
					Start: i, End: end, Token: s[i:end]})
				i = end
				continue
			}
			i++
		}

		// PEM 私钥块
		if idx := strings.Index(s, "-----BEGIN"); idx >= 0 {
			if strings.Contains(s[idx:], "PRIVATE KEY-----") {
				end := strings.Index(s[idx:], "-----END")
				if end < 0 {
					end = len(s) - idx
				} else {
					if e2 := strings.Index(s[idx+end:], "-----"); e2 >= 0 {
						end = end + e2 + 5
					}
				}
				findings = append(findings, SLKFinding{Reason: SLKReasonPrivateKeyPEM,
					Start: idx, End: idx + end, Token: "PEM-PRIVATE-KEY"})
			}
		}

		// JWT：eyJ 头，三段以 '.' 分隔，整体是令牌字符
		i = 0
		for {
			j := indexSubstrSLK(s[i:], "eyJ")
			if j < 0 {
				break
			}
			at := i + j
			end := slkTokenEnd(s, at)
			tok := s[at:end]
			dots := 0
			for k := 0; k < len(tok); k++ {
				if tok[k] == '.' {
					dots++
				}
			}
			if dots >= 2 && len(tok) >= 16 {
				findings = append(findings, SLKFinding{Reason: SLKReasonJWT,
					Start: at, End: end, Token: tok})
			}
			i = end
			if i <= at {
				i = at + 1
			}
		}
	}

	if policy.DetectAssignments {
		lower := strings.ToLower(s)
		keys := []string{"authorization: bearer ", "authorization:basic ",
			"password=", "passwd=", "secret=", "token=", "access_token=",
			"refresh_token=", "api_key=", "apikey=", "client_secret="}
		for _, k := range keys {
			from := 0
			for {
				pos := indexSubstrSLK(lower[from:], k)
				if pos < 0 {
					break
				}
				abs := from + pos
				vstart := abs + len(k)
				// 跳过空白
				for vstart < len(s) && (s[vstart] == ' ' || s[vstart] == '\t') {
					vstart++
				}
				vend := vstart
				for vend < len(s) && slkIsTokenChar(s[vend]) {
					vend++
				}
				if vend > vstart {
					reason := SLKReasonAssignment
					if k == "authorization: bearer " {
						reason = SLKReasonBearerHeader
					}
					findings = append(findings, SLKFinding{Reason: reason,
						Start: vstart, End: vend, Token: s[vstart:vend]})
				}
				from = abs + len(k)
			}
		}
	}

	if policy.DetectHighEntropy && policy.EntropyMinLen > 0 {
		i := 0
		for i < len(s) {
			if slkIsTokenChar(s[i]) {
				end := slkTokenEnd(s, i)
				run := s[i:end]
				if len(run) >= policy.EntropyMinLen &&
					slkDistinct(run) >= policy.EntropyMinDistinct &&
					slkContainsDigitAndLetter(run) {
					findings = append(findings, SLKFinding{Reason: SLKReasonHighEntropy,
						Start: i, End: end, Token: run})
				}
				i = end
				continue
			}
			i++
		}
	}

	findings = slkMergeOverlaps(findings)
	return len(findings) == 0, findings
}

func slkContainsDigitAndLetter(s string) bool {
	digit, letter := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			digit = true
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			letter = true
		}
	}
	return digit && letter
}

func indexSubstrSLK(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// slkMergeOverlaps 合并重叠/包含的命中，保留更靠后加入的具体类型优先级。
func slkMergeOverlaps(in []SLKFinding) []SLKFinding {
	if len(in) < 2 {
		return in
	}
	// 简单冒泡式合并被其它区间包含的项。
	keep := make([]bool, len(in))
	for i := range in {
		keep[i] = true
	}
	for i := 0; i < len(in); i++ {
		for j := 0; j < len(in); j++ {
			if i == j || !keep[i] || !keep[j] {
				continue
			}
			// 若 i 被 j 包含且 i 是高熵这类弱信号，丢 i。
			if in[j].Start <= in[i].Start && in[i].End <= in[j].End &&
				in[i].Reason == SLKReasonHighEntropy && in[j].Reason != SLKReasonHighEntropy {
				keep[i] = false
			}
		}
	}
	out := make([]SLKFinding, 0, len(in))
	for i := range in {
		if keep[i] {
			out = append(out, in[i])
		}
	}
	return out
}

// SLKRedact 把命中的令牌替换成等长掩码（保留前 4 位便于定位），其余字符用 MaskRune。
func SLKRedact(text string, findings []SLKFinding, policy SLKPolicy) string {
	if len(findings) == 0 {
		return text
	}
	mask := policy.MaskRune
	if mask == 0 {
		mask = '*'
	}
	b := []byte(text)
	for _, f := range findings {
		for k := f.Start; k < f.End && k < len(b); k++ {
			b[k] = mask
		}
		// 保留前 4 个字符作为定位提示（对足够长的令牌）。
		if f.End-f.Start >= 12 {
			for k := f.Start; k < f.Start+4 && k < len(b); k++ {
				b[k] = text[k]
			}
		}
	}
	return string(b)
}

// 确保 slkLower 被使用（供未来键名大小写归一）。
var _ = slkLower
