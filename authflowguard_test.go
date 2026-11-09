package main

// authflowguard_test.go —— OAuth 流程守卫内核的测试。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateOAuthState(t *testing.T) {
	var lim0 AuthFlowLimits
	lim := lim0.withDefaults()
	good := ValidateOAuthState("abc123", "abc123", lim)
	if !good.Ok {
		t.Errorf("matching state rejected: %v", good.Reasons)
	}
	bad := ValidateOAuthState("abc124", "abc123", lim)
	if bad.Ok {
		t.Error("mismatched state accepted")
	}
	if len(bad.Reasons) == 0 || !strings.Contains(bad.Reasons[0], "CSRF") {
		t.Errorf("expected CSRF reason, got %v", bad.Reasons)
	}
	empty := ValidateOAuthState("", "x", lim)
	if empty.Ok {
		t.Error("empty state accepted")
	}
	long := ValidateOAuthState(strings.Repeat("a", 300), strings.Repeat("a", 300), lim)
	if long.Ok {
		t.Error("overlong state accepted")
	}
	ctrl := ValidateOAuthState("a\x01b", "a\x01b", lim)
	if ctrl.Ok {
		t.Error("control-char state accepted")
	}
}

func TestAuthHostMatches(t *testing.T) {
	good := []string{
		"login.microsoftonline.com",
		"login.live.com",
		"sub.login.microsoftonline.com",
		"login.msa.azurefd.net",
		"graph.microsoft.com",
	}
	bad := []string{
		"",
		"evil.com",
		"login.microsoftonline.com.evil.com",
		"microsoftonline.com",
		"login.live.com.evil.net",
		"https://login.live.com",
	}
	for _, h := range good {
		if !authHostMatches(h) {
			t.Errorf("host %q should match", h)
		}
	}
	for _, h := range bad {
		if authHostMatches(h) {
			t.Errorf("host %q should not match", h)
		}
	}
}

func TestValidateRedirectURI(t *testing.T) {
	var lim0 AuthFlowLimits
	lim := lim0.withDefaults()
	good := []string{
		"https://login.microsoftonline.com/oauth20/authorize",
		"https://login.live.com/oauth20/desktop",
		"https://login.microsoftonline.com/oauth/v20/authorize/code",
		"https://login.msa.azurefd.net/consumers/oauth2/v2.0/authorize",
	}
	bad := []string{
		"",
		"http://login.live.com/oauth20/authorize",           // 明文
		"https://evil.com/oauth20/authorize",                 // 非白名单主机
		"https://login.live.com.evil.com/oauth20/authorize",  // 后缀欺骗
		"https://login.live.com/oauth20/authorize?x=1",       // 带 query
		"https://login.live.com/oauth20/authorize#frag",      // 带 fragment
		"https://login.live.com/",                            // 路径不在白名单
		"https://login.live.com/oauth20/../admin",            // 路径穿越
		"https://login.live.com",                             // 缺路径
		"https://login.live.com/oauth20/authorize\x00x",      // 控制字符
	}
	for _, u := range good {
		v := ValidateRedirectURI(u, lim)
		if !v.Ok {
			t.Errorf("redirect %q rejected: %v", u, v.Reasons)
		}
	}
	for _, u := range bad {
		v := ValidateRedirectURI(u, lim)
		if v.Ok {
			t.Errorf("redirect %q accepted", u)
		}
	}
}

func TestScopeAllowed(t *testing.T) {
	good := []string{"XboxLive.signin", "offline_access", "openid", "profile", "email", "User.Read"}
	bad := []string{"", "mail.read", "user.readwrite", "XboxLive.signin.evil", "Directory.AccessAsUser.All"}
	for _, s := range good {
		if !scopeAllowed(s) {
			t.Errorf("scope %q should be allowed", s)
		}
	}
	for _, s := range bad {
		if scopeAllowed(s) {
			t.Errorf("scope %q should be rejected", s)
		}
	}
}

func TestValidateAuthToken(t *testing.T) {
	var lim0 AuthFlowLimits
	lim := lim0.withDefaults()
	now := unixNow()
	good := ValidateAuthToken("tok-" + strings.Repeat("a", 40), now+3600, []string{"XboxLive.signin", "offline_access"}, lim)
	if !good.Ok {
		t.Errorf("valid token rejected: %v", good.Reasons)
	}
	empty := ValidateAuthToken("", now+3600, nil, lim)
	if empty.Ok {
		t.Error("empty token accepted")
	}
	long := ValidateAuthToken(strings.Repeat("a", 10000), now+3600, nil, lim)
	if long.Ok {
		t.Error("overlong token accepted")
	}
	ctrl := ValidateAuthToken("tok\x00x", now+3600, nil, lim)
	if ctrl.Ok {
		t.Error("control-char token accepted")
	}
	expired := ValidateAuthToken("tok", now-1, nil, lim)
	if expired.Ok {
		t.Error("expired token accepted")
	}
	noExpiry := ValidateAuthToken("tok", 0, nil, lim)
	if noExpiry.Ok {
		t.Error("token without expiry accepted")
	}
	tooFar := ValidateAuthToken("tok", now+lim.TokenLifetimeSec*2, nil, lim)
	if tooFar.Ok {
		t.Error("token with absurd lifetime accepted")
	}
	badScope := ValidateAuthToken("tok", now+3600, []string{"Directory.AccessAsUser.All"}, lim)
	if badScope.Ok {
		t.Error("token with forbidden scope accepted")
	}
}

func TestCheckTokenFilePerm(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "token.json")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, reason := CheckTokenFilePerm(p)
	if !ok {
		t.Errorf("0600 token file rejected: %s", reason)
	}
	// Windows 无 POSIX 位，直接接受；POSIX 上 0644 必须被拒
	if err := os.Chmod(p, 0o644); err == nil {
		ok2, reason2 := CheckTokenFilePerm(p)
		if ok2 && !strings.Contains(reason2, "windows") {
			t.Errorf("0644 should be rejected on posix, got ok: %s", reason2)
		}
	}
	missing, _ := CheckTokenFilePerm(filepath.Join(dir, "nope.json"))
	if missing {
		t.Error("missing token file accepted")
	}
}

func TestSummarizeAuthVerdict(t *testing.T) {
	ok := AuthVerdict{Ok: true}
	if s := SummarizeAuthVerdict(ok); s != "auth check ok" {
		t.Errorf("unexpected ok summary: %s", s)
	}
	bad := AuthVerdict{Ok: false, Reasons: []string{"state mismatch (possible CSRF)"}}
	s := SummarizeAuthVerdict(bad)
	if !strings.Contains(s, "FAILED") || !strings.Contains(s, "CSRF") {
		t.Errorf("unexpected bad summary: %s", s)
	}
	if UnwrapAuthError(bad) == nil {
		t.Error("UnwrapAuthError should return error for failed verdict")
	}
	if UnwrapAuthError(ok) != nil {
		t.Error("UnwrapAuthError should return nil for ok verdict")
	}
}
