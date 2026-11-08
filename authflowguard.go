package main

// authflowguard.go —— 微软/第三方 OAuth 登录流程的防 CSRF 与令牌校验内核。
//
// 背景：
//   启动器用微软 OAuth 登录换取 access token。回调链路里有几类真实攻击面：
//     1) 回调 URL 缺少/弱校验 state —— 攻击者把自己的授权码塞进回调，配合浏览器
//        历史/侧信道可做登录态绑架（login CSRF）；
//     2) 重定向 URI 校验过松 —— 允许非白名单主机/明文 http/带查询参数的回调，
//        授权码会被中间人或恶意页面截获；
//     3) token 落盘权限过宽 —— 任何人可读的 token 文件等于把会话直接送人；
//     4) 令牌字段不校验 —— 过期/超长/含控制字符的 token 被当作有效凭据使用。
//   本模块只做校验与结论上报，不触碰网络与凭据存储本身（存储逻辑在调用方）。
//
// 设计要点：
//   - state 恒时比较（subtle.ConstantTimeCompare），限长、拒控制字符；
//   - redirect_uri 必须 https + 主机白名单（精确/子域匹配）+ 路径白名单前缀，
//     禁 query/fragment（回调地址不允许带参数，防注入）；
//   - token 校验：限长、拒控制字符、expires_at 必须未过期且给合理上限、
//     scope 必须是白名单子集（逐项比对，防越权 scope 注入）；
//   - 本地 token 文件权限检查：POSIX 下必须 0600，Windows 无 POSIX 位则跳过
//     （Windows 上文件 ACL 由调用方负责，这里只做能力提示）。

import (
	"crypto/subtle"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// AuthFlowLimits 限定 OAuth 流程各输入的长度与有效期边界。
type AuthFlowLimits struct {
	MaxStateRunes    int
	MaxTokenRunes    int
	MaxCodeRunes     int
	TokenLifetimeSec int64
}

func (l *AuthFlowLimits) withDefaults() AuthFlowLimits {
	if l == nil {
		l = &AuthFlowLimits{}
	}
	out := *l
	if out.MaxStateRunes <= 0 {
		out.MaxStateRunes = 128
	}
	if out.MaxTokenRunes <= 0 {
		out.MaxTokenRunes = 4096
	}
	if out.MaxCodeRunes <= 0 {
		out.MaxCodeRunes = 512
	}
	if out.TokenLifetimeSec <= 0 {
		out.TokenLifetimeSec = 86400
	}
	return out
}

// AuthVerdict 是 OAuth 校验的结构化结论。
type AuthVerdict struct {
	Ok      bool
	Reasons []string // 未通过的理由，可多条
}

func (v *AuthVerdict) fail(reason string) {
	v.Ok = false
	v.Reasons = append(v.Reasons, reason)
}

func (v *AuthVerdict) ok() {
	v.Ok = true
}

// authHosts 是允许作为 OAuth 回调/授权跳转目标的官方主机（精确或子域）。
var authHosts = []string{
	"login.microsoftonline.com",
	"login.live.com",
	"login.msa.azurefd.net",
	"graph.microsoft.com",
}

// authPathPrefixes 是允许的回调路径前缀。
var authPathPrefixes = []string{
	"/oauth20/authorize",
	"/oauth20/desktop",
	"/oauth/v20/authorize",
	"/consumers/oauth2/v2.0/authorize",
}

// ValidateOAuthState 校验回调携带的 state 是否与本地发起时保存的 state 恒时一致。
func ValidateOAuthState(state, stored string, lim AuthFlowLimits) AuthVerdict {
	v := AuthVerdict{}
	d := lim.withDefaults()
	if strings.TrimSpace(state) == "" || strings.TrimSpace(stored) == "" {
		v.fail("state must not be empty")
		return v
	}
	if len([]rune(state)) > d.MaxStateRunes || len([]rune(stored)) > d.MaxStateRunes {
		v.fail("state exceeds length limit")
		return v
	}
	if hasControlCharStr(state) || hasControlCharStr(stored) {
		v.fail("state contains control characters")
		return v
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(stored)) != 1 {
		v.fail("state mismatch (possible CSRF)")
		return v
	}
	v.ok()
	return v
}

// authHostMatches 判断 host 是否命中白名单（精确或子域）。
func authHostMatches(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	for _, allowed := range authHosts {
		if h == allowed {
			return true
		}
		if strings.HasSuffix(h, "."+allowed) {
			return true
		}
	}
	return false
}

// ValidateRedirectURI 校验回调地址：https、白名单主机、白名单路径前缀、无 query/fragment。
func ValidateRedirectURI(uri string, lim AuthFlowLimits) AuthVerdict {
	v := AuthVerdict{}
	d := lim.withDefaults()
	if len([]rune(uri)) > d.MaxStateRunes*8 {
		v.fail("redirect uri too long")
		return v
	}
	if hasControlCharStr(uri) {
		v.fail("redirect uri contains control characters")
		return v
	}
	if !strings.HasPrefix(uri, "https://") {
		v.fail("redirect uri must be https")
		return v
	}
	rest := uri[len("https://"):]
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		host := rest[:i]
		path := rest[i:]
		if !authHostMatches(host) {
			v.fail("redirect host not allowed")
			return v
		}
		if q := strings.IndexAny(path, "?#"); q >= 0 {
			v.fail("redirect uri must not carry query or fragment")
			return v
		}
		okPath := false
		for _, p := range authPathPrefixes {
			if path == p || strings.HasPrefix(path, p+"/") {
				okPath = true
				break
			}
		}
		if !okPath {
			v.fail("redirect path not allowed")
			return v
		}
		v.ok()
		return v
	}
	v.fail("redirect uri missing path")
	return v
}

// allowedScopes 是启动器请求的最小 scope 白名单；请求只能命中其子集。
var allowedScopes = []string{
	"XboxLive.signin",
	"offline_access",
	"openid",
	"profile",
	"email",
	"User.Read",
}

// scopeAllowed 判断单个 scope 是否在白名单内。
func scopeAllowed(scope string) bool {
	for _, s := range allowedScopes {
		if scope == s {
			return true
		}
	}
	return false
}

// ValidateAuthToken 校验 access token 的形态与有效期。
func ValidateAuthToken(token string, expiresAtSec int64, scopes []string, lim AuthFlowLimits) AuthVerdict {
	v := AuthVerdict{}
	d := lim.withDefaults()
	if strings.TrimSpace(token) == "" {
		v.fail("token must not be empty")
		return v
	}
	if len([]rune(token)) > d.MaxTokenRunes {
		v.fail("token exceeds length limit")
		return v
	}
	if hasControlCharStr(token) {
		v.fail("token contains control characters")
		return v
	}
	if expiresAtSec <= 0 {
		v.fail("token missing expiry")
		return v
	}
	now := unixNow()
	if expiresAtSec <= now {
		v.fail("token already expired")
		return v
	}
	if expiresAtSec > now+d.TokenLifetimeSec {
		v.fail("token lifetime exceeds configured ceiling")
		return v
	}
	for _, s := range scopes {
		if !scopeAllowed(s) {
			v.fail("scope not allowed: " + s)
			return v
		}
	}
	v.ok()
	return v
}

// unixNow 提取为函数便于测试注入。
var unixNow = func() int64 {
	return time.Now().Unix()
}

// CheckTokenFilePerm 校验本地令牌文件的权限：POSIX 下必须非组/非他可读（0600）。
// Windows 无 POSIX 权限位，返回 true 由调用方走 ACL 检查。
func CheckTokenFilePerm(path string) (bool, string) {
	if runtime.GOOS == "windows" {
		return true, "windows-acl-out-of-scope"
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, "cannot stat token file: " + err.Error()
	}
	perm := info.Mode().Perm()
	if perm&0o077 != 0 {
		return false, "token file permissions too broad: " + strconv.FormatUint(uint64(perm), 8)
	}
	return true, "perm-ok"
}

// SummarizeAuthVerdict 把校验结论压成简短可读文本。
func SummarizeAuthVerdict(v AuthVerdict) string {
	if v.Ok {
		return "auth check ok"
	}
	return "auth check FAILED: " + strings.Join(v.Reasons, "; ")
}

// UnwrapAuthError 把 AuthVerdict 转成标准 error（用于需要 error 的调用点）。
func UnwrapAuthError(v AuthVerdict) error {
	if v.Ok {
		return nil
	}
	return errors.New(SummarizeAuthVerdict(v))
}
