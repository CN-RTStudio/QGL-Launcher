package main

import (
	"crypto/subtle"
	"strings"
)

func scopeAllowed(scope string) bool {
	for _, s := range allowedScopes {
		if scope == s {
			return true
		}
	}
	return false
}
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
