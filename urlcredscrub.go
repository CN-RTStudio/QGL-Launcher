package main

// urlcredscrub.go —— 结构化 URL 的凭据脱敏（供日志、审计台账、重定向记录复用）。
//
// 与 reportmin.scrubURLTokens 的区别：
//   scrubURLTokens 对“一段自由文本”做整体令牌扫描，宁错杀地把疑似高熵串抹掉；
//   本模块针对一个已经解析好的 *url.URL（或合法 URL 字符串）做结构化处理：
//   保留 scheme/host/path 的可辨识度（排障仍看得出去了哪个站点、哪个接口），
//   只对真正承载秘密的位置做精确替换：
//     - userinfo 里的密码（https://user:pass@host）→ user:***；
//     - query 中按“敏感参数键名”命中的值 → [REDACTED]；
//     - query 中即使键名良性、值却呈高熵令牌形态（JWT/长 hex/长 base64url/
//       Bearer）的参数 → [REDACTED]，避免站点把 token 放在 ?id=、?data= 里漏网；
//     - fragment 在 OAuth implicit 流里常携带 access_token，按策略整体丢弃；
//     - 空值与明显非敏感的短值（分页号、版本号）原样保留。
//
// 该结果只用于“记录/外发非首方”，绝不回写进真正的请求 URL（真实请求仍需携带
// 凭据）。纯函数，不发请求、不读环境。

import (
	"net/url"
	"sort"
	"strings"
)

// URLRedaction 记录一处脱敏命中，便于审计统计。
type URLRedaction struct {
	Location string // "userinfo" / "query" / "fragment"
	Key      string // query 参数键；其余位置为空
	Reason   string
}

// URLScrubPolicy 控制脱敏策略。
type URLScrubPolicy struct {
	// KeepSafeQuery 为始终保留原样的参数键（小写），如分页、版本、语言。
	KeepSafeQuery map[string]struct{}
	// ExtraSensitiveQuery 为在默认敏感键之外追加的参数键（小写）。
	ExtraSensitiveQuery map[string]struct{}
	// DropFragment 为 true 时整个 fragment 丢弃（OAuth/含秘场景建议开启）。
	DropFragment bool
	// MinHighEntropyLen 触发“良性键但高熵值”脱敏的最小长度；<=0 用默认。
	MinHighEntropyLen int
}

// 默认敏感 query 参数键（小写）。覆盖常见凭据/签名/会话/重置令牌命名。
var defaultSensitiveQueryKeys = map[string]struct{}{
	"access_token": {}, "accesstoken": {}, "token": {}, "id_token": {},
	"refresh_token": {}, "session": {}, "sessionid": {}, "sid": {},
	"password": {}, "passwd": {}, "pwd": {}, "pass": {},
	"secret": {}, "client_secret": {}, "api_key": {}, "apikey": {},
	"key": {}, "signature": {}, "sig": {}, "sign": {}, "auth": {},
	"authorization": {}, "code": {}, "authcode": {}, "otp": {},
	"reset_token": {}, "verify": {}, "ticket": {}, "st": {},
	"proxy_auth": {}, "bearer": {},
}

func defaultURLScrubPolicy() URLScrubPolicy {
	return URLScrubPolicy{
		KeepSafeQuery: map[string]struct{}{
			"page": {}, "size": {}, "limit": {}, "offset": {}, "v": {},
			"version": {}, "lang": {}, "locale": {}, "format": {},
		},
		DropFragment:      true,
		MinHighEntropyLen: 28,
	}
}

// ScrubURL 对已解析 URL 做脱敏，返回可安全记录的字符串与命中明细。
// 不修改传入的 u（内部克隆）。
func ScrubURL(u *url.URL, policy URLScrubPolicy) (string, []URLRedaction) {
	if u == nil {
		return "", nil
	}
	if policy.MinHighEntropyLen <= 0 {
		policy = defaultURLScrubPolicy()
	}
	var reds []URLRedaction
	clone := *u // 浅拷贝；下方只替换标量字段与重建的 query，不改原 map

	// 1) userinfo。
	if clone.User != nil {
		if _, hasPw := clone.User.Password(); hasPw {
			reds = append(reds, URLRedaction{Location: "userinfo", Reason: "userinfo-password"})
		}
		clone.User = url.UserPassword(scrubUserInfoName(clone.User.Username()), "***")
	}

	// 2) query 逐键处理（保持键顺序稳定，便于测试与日志 diff）。
	if clone.RawQuery != "" {
		scrubbedQuery, qReds := scrubQuery(clone.Query(), policy)
		clone.RawQuery = scrubbedQuery
		reds = append(reds, qReds...)
	}

	// 3) fragment。
	if clone.Fragment != "" {
		if policy.DropFragment || fragmentLooksSensitive(clone.Fragment, policy) {
			reds = append(reds, URLRedaction{Location: "fragment", Reason: "fragment-dropped"})
			clone.Fragment = ""
		}
	}

	return clone.String(), reds
}

// ScrubURLString 解析后脱敏；解析失败时退化为保守输出（仅 scheme://host，不
// 泄露原始 query/fragment）。
func ScrubURLString(raw string, policy URLScrubPolicy) (string, []URLRedaction) {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return "(unparseable-url)", []URLRedaction{{Location: "query", Reason: "unparseable-url"}}
	}
	return ScrubURL(u, policy)
}

func scrubUserInfoName(name string) string {
	// 用户名通常不敏感，但极端情况下会把邮箱/账号放进 userinfo；保留可读首字符。
	if name == "" {
		return ""
	}
	if len(name) <= 2 {
		return strings.Repeat("*", len(name))
	}
	return string(name[0]) + strings.Repeat("*", len(name)-1)
}

// scrubQuery 重建 query：敏感键值/高熵值替换为 [REDACTED]，其余保留。
// 输出按原始出现顺序重建（url.Values 会丢序，因此这里直接解析 RawQuery）。
func scrubQuery(values url.Values, policy URLScrubPolicy) (string, []URLRedaction) {
	var reds []URLRedaction
	kept := url.Values{}
	// 用已解析 values 做决策，但顺序由 encode 排序保证稳定（测试可预期）。
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		low := strings.ToLower(k)
		if _, keep := policy.KeepSafeQuery[low]; keep {
			kept[k] = values[k]
			continue
		}
		sensitiveByKey := isSensitiveQueryKey(low, policy)
		vals := values[k]
		newVals := make([]string, len(vals))
		for i, v := range vals {
			reason := ""
			if sensitiveByKey {
				reason = "sensitive-query-key"
			} else if valueLooksHighEntropy(v, policy.MinHighEntropyLen) {
				reason = "high-entropy-query-value"
			}
			if reason != "" && v != "" {
				newVals[i] = "[REDACTED]"
				reds = append(reds, URLRedaction{Location: "query", Key: k, Reason: reason})
			} else {
				newVals[i] = v
			}
		}
		kept[k] = newVals
	}
	return kept.Encode(), reds
}

func isSensitiveQueryKey(low string, policy URLScrubPolicy) bool {
	if _, ok := defaultSensitiveQueryKeys[low]; ok {
		return true
	}
	if policy.ExtraSensitiveQuery != nil {
		if _, ok := policy.ExtraSensitiveQuery[low]; ok {
			return true
		}
	}
	return false
}

// fragmentLooksSensitive 检测 OAuth implicit 风格 fragment（key=token&...）。
func fragmentLooksSensitive(frag string, policy URLScrubPolicy) bool {
	if frag == "" {
		return false
	}
	// fragment 可能是 'k=v&k2=v2' 或纯锚点；含 '=' 时按键名检查。
	if strings.Contains(frag, "=") {
		for _, pair := range strings.Split(frag, "&") {
			eq := strings.IndexByte(pair, '=')
			if eq < 0 {
				continue
			}
			if isSensitiveQueryKey(strings.ToLower(pair[:eq]), policy) {
				return true
			}
		}
	}
	return false
}

// valueLooksHighEntropy 识别良性键下的高熵秘密值：
//   - JWT 三段式；
//   - 长十六进制；
//   - 长 base64url；
//   - 形如 "Bearer xxx"。
// 不使用正则，逐字符判断。短数字/版本号/分页值天然不达长度阈值。
func valueLooksHighEntropy(v string, minLen int) bool {
	if minLen <= 0 {
		minLen = 28
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	low := strings.ToLower(v)
	if strings.HasPrefix(low, "bearer ") {
		return tokenish(low[len("bearer "):], minLen)
	}
	return tokenish(v, minLen)
}

func tokenish(s string, minLen int) bool {
	if jwtLike(s) {
		return true
	}
	if len(s) >= minLen && allHex(s) {
		return true
	}
	if len(s) >= minLen && !strings.ContainsAny(s, " /\\") && allBase64URL(s) {
		return true
	}
	return false
}

func jwtLike(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) < 4 || !allBase64URL(p) {
			return false
		}
	}
	return true
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

func allBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok && !(c == '=' && i >= len(s)-2) {
			return false
		}
	}
	return len(s) > 0
}

// HasSensitiveRedaction 便于调用方快速判断该 URL 是否含被脱敏的秘密。
func HasSensitiveRedaction(reds []URLRedaction) bool {
	return len(reds) > 0
}
