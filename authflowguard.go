package main

import (
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

var unixNow = func() int64 {
	return time.Now().Unix()
}

// CheckTokenFilePerm 校验本地令牌文件的权限：POSIX 下必须非组/非他可读（0600）。
// Windows 无 POSIX 权限位，返回 true 由调用方走 ACL 检查。
