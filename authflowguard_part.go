package main

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
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
