package main

import (
	"strings"
)

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
