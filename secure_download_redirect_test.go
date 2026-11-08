package main

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func newReqURL(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		t.Fatalf("构造请求失败 %s: %v", raw, err)
	}
	return req
}

func TestSecureDownloadRedirectRejectsInsecureHop(t *testing.T) {
	via := []*http.Request{newReqURL(t, "https://piston-data.mojang.com/v1/a")}
	next := newReqURL(t, "http://mirror.example.com/v1/a")
	if err := secureDownloadCheckRedirect(next, via, nil); err == nil {
		t.Fatal("http 跳转应被拒绝")
	}
}

func TestSecureDownloadRedirectRejectsUserinfoHop(t *testing.T) {
	via := []*http.Request{newReqURL(t, "https://cdn.example.net/a")}
	next := newReqURL(t, "https://cdn.example.net@evil.example.org/a")
	err := secureDownloadCheckRedirect(next, via, nil)
	if !errors.Is(err, errSecureDownloadBadRedirect) {
		t.Fatalf("userinfo 跳转应被拒绝，实际: %v", err)
	}
}

func TestSecureDownloadRedirectRejectsLoop(t *testing.T) {
	first := newReqURL(t, "https://cdn.example.net/a")
	second := newReqURL(t, "https://cdn.example.net/b")
	via := []*http.Request{first, second}
	next := newReqURL(t, "https://cdn.example.net/a")
	err := secureDownloadCheckRedirect(next, via, nil)
	if !errors.Is(err, errSecureDownloadBadRedirect) {
		t.Fatalf("跳转环应被拒绝，实际: %v", err)
	}
}

func TestSecureDownloadRedirectKeepsInnerPolicy(t *testing.T) {
	innerErr := errors.New("mod 白名单拒绝")
	inner := func(req *http.Request, via []*http.Request) error { return innerErr }
	via := []*http.Request{newReqURL(t, "https://cdn.example.net/a")}
	next := newReqURL(t, "https://other.example.net/b")
	if err := secureDownloadCheckRedirect(next, via, inner); !errors.Is(err, innerErr) {
		t.Fatalf("调用方策略应先失败，实际: %v", err)
	}
}

func TestSecureDownloadRedirectAllowsSameHostHTTPS(t *testing.T) {
	via := []*http.Request{newReqURL(t, "https://cdn.example.net/a")}
	next := newReqURL(t, "https://cdn.example.net/b")
	if err := secureDownloadCheckRedirect(next, via, nil); err != nil {
		t.Fatalf("同主 https 跳转应放行: %v", err)
	}
}

func TestWrapClientRedirectGuardDoesNotMutateSource(t *testing.T) {
	src := &http.Client{Timeout: 30 * time.Second}
	if src.CheckRedirect != nil {
		t.Fatal("前置条件不成立")
	}
	guarded := wrapClientRedirectGuard(src)
	if guarded == src {
		t.Fatal("应返回副本而不是就地修改")
	}
	if src.CheckRedirect != nil {
		t.Fatal("原始客户端不应被改写")
	}
	if guarded.CheckRedirect == nil || guarded.Timeout != src.Timeout {
		t.Fatal("副本应保留超时并装上重定向守卫")
	}
}

func TestServerFilenameFromHeaderAcceptsSafeName(t *testing.T) {
	if got := serverFilenameFromHeader(`attachment; filename="mod-1.2.3.jar"`); got != "mod-1.2.3.jar" {
		t.Fatalf("安全文件名应保留，实际 %q", got)
	}
	if got := serverFilenameFromHeader(`attachment; filename="fb.bin"; filename*=UTF-8''real.jar`); got != "real.jar" {
		t.Fatalf("filename* 应优先，实际 %q", got)
	}
	if got := serverFilenameFromHeader(""); got != "" {
		t.Fatalf("空头应返回空串，实际 %q", got)
	}
}

func TestServerFilenameFromHeaderDropsUnsafeName(t *testing.T) {
	cases := []string{
		`attachment; filename="a.jar:payload"`,
		`attachment; filename="../../evil.jar"`,
		`attachment; filename="CON"`,
		`attachment; filename="a. "`,
		`attachment; filename="a<b>.jar"`,
		"attachment; filename=\"a\u202eevil.jar\"",
	}
	for _, h := range cases {
		if got := serverFilenameFromHeader(h); got != "" {
			t.Fatalf("不安全文件名应丢弃，头 %s 得到 %q", h, got)
		}
	}
}
