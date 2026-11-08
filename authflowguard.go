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
	"strings"
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
