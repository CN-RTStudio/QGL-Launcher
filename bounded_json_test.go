package main

// bounded_json_test.go 覆盖有界 JSON 拉取助手：正常解析、声明/实际体积
// 超限、非 JSON 媒体类型拒绝、503 退避重试、404 不重试、明文 URL 拒绝、
// 缺限拒绝、镜像顺序回退、媒体类型解析工具。

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type jsonTestPayload struct {
	Version int    `json:"version"`
	Name    string `json:"name"`
}

func jsonTestOptions(max int64) jsonFetchOptions {
	return jsonFetchOptions{
		MaxBytes:        max,
		Attempts:        3,
		AllowMediaTypes: []string{"application/json"},
		SourceLabel:     "测试元数据",
	}
}

func TestParseMediaType(t *testing.T) {
	cases := map[string]string{
		"application/json; charset=utf-8": "application/json",
		"  Application/JSON ":             "application/json",
		"text/html":                       "text/html",
		"":                                "",
	}
	for in, want := range cases {
		if got := parseMediaType(in); got != want {
			t.Errorf("parseMediaType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMediaTypeAllowed(t *testing.T) {
	if !mediaTypeAllowed("application/json", []string{"application/json", "text/plain"}) {
		t.Error("白名单命中应放行")
	}
	if mediaTypeAllowed("text/html", []string{"application/json"}) {
		t.Error("白名单未命中应拒绝")
	}
	if !mediaTypeAllowed("anything/at-all", nil) {
		t.Error("空白名单应视为不校验")
	}
}

func TestReadBoundedBody(t *testing.T) {
	data, err := readBoundedBody(strings.NewReader("12345"), 5)
	if err != nil || string(data) != "12345" {
		t.Fatalf("恰好在限内应读全，得到 %q err=%v", data, err)
	}
	if _, err := readBoundedBody(strings.NewReader("123456"), 5); err != errJSONFetchTooLarge {
		t.Fatalf("多读 1 字节应报超限，得到 err=%v", err)
	}
}

func newJSONTLSServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, jsonFetchOptions) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	opts := jsonTestOptions(1 << 20)
	opts.Client = srv.Client()
	return srv, opts
}

func TestFetchJSONBoundedOK(t *testing.T) {
	srv, opts := newJSONTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, `{"version":7,"name":"ok"}`)
	})
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var p jsonTestPayload
	if err := fetchJSONBounded(ctx, srv.URL, &p, opts); err != nil {
		t.Fatalf("正常拉取失败: %v", err)
	}
	if p.Version != 7 || p.Name != "ok" {
		t.Fatalf("反序列化结果错误: %+v", p)
	}
}

func TestFetchJSONBoundedDeclaredTooLarge(t *testing.T) {
	srv, opts := newJSONTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		// 声明 999999 但实际不发：客户端必须在读体之前仅凭头拒绝。
		// 不能阻塞：测试结束后 httptest 会等待 handler 返回。
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "999999")
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()
	opts.MaxBytes = 1024
	var p jsonTestPayload
	err := fetchJSONBounded(context.Background(), srv.URL, &p, opts)
	if err == nil || !strings.Contains(err.Error(), "超过上限") {
		t.Fatalf("声明超限应拒绝，得到 %v", err)
	}
}

func TestFetchJSONBoundedActualTooLargeChunked(t *testing.T) {
	big := strings.Repeat("a", 4096)
	srv, opts := newJSONTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		fmt.Fprint(w, big) // 分块、无 Content-Length
	})
	defer srv.Close()
	opts.MaxBytes = 256
	var p jsonTestPayload
	err := fetchJSONBounded(context.Background(), srv.URL, &p, opts)
	if err == nil || !strings.Contains(err.Error(), "超过上限") {
		t.Fatalf("实际超限应拒绝，得到 %v", err)
	}
}

func TestFetchJSONBoundedBadMediaType(t *testing.T) {
	srv, opts := newJSONTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html>bad gateway page</html>`)
	})
	defer srv.Close()
	var p jsonTestPayload
	err := fetchJSONBounded(context.Background(), srv.URL, &p, opts)
	if err == nil || !strings.Contains(err.Error(), "媒体类型") {
		t.Fatalf("HTML 伪装成 JSON 必须按媒体类型拒绝，得到 %v", err)
	}
}

func TestFetchJSONBoundedRetriesOn503(t *testing.T) {
	var hits int
	srv, opts := newJSONTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":9,"name":"retry"}`)
	})
	defer srv.Close()
	// 缩短退避，避免测试等待太久。
	old := jsonFetchBackoffBase
	jsonFetchBackoffBase = time.Millisecond
	defer func() { jsonFetchBackoffBase = old }()

	var p jsonTestPayload
	if err := fetchJSONBounded(context.Background(), srv.URL, &p, opts); err != nil {
		t.Fatalf("503 后第二次应成功: %v", err)
	}
	if hits != 2 {
		t.Fatalf("应只请求 2 次，实际 %d", hits)
	}
}

func TestFetchJSONBoundedNoRetryOn404(t *testing.T) {
	var hits int
	srv, opts := newJSONTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotFound)
	})
	defer srv.Close()
	var p jsonTestPayload
	_ = fetchJSONBounded(context.Background(), srv.URL, &p, opts)
	if hits != 1 {
		t.Fatalf("404 不应重试，实际请求 %d 次", hits)
	}
}

func TestFetchJSONBoundedRejectsPlainHTTP(t *testing.T) {
	var p jsonTestPayload
	err := fetchJSONBounded(context.Background(), "http://insecure.test/x.json", &p, jsonTestOptions(1024))
	if err == nil || !strings.Contains(err.Error(), "非 HTTPS") {
		t.Fatalf("明文 HTTP 必须拒绝，得到 %v", err)
	}
}

func TestFetchJSONBoundedRequiresLimit(t *testing.T) {
	srv, _ := newJSONTLSServer(t, func(w http.ResponseWriter, r *http.Request) {})
	defer srv.Close()
	var p jsonTestPayload
	opts := jsonFetchOptions{Client: srv.Client()}
	if err := fetchJSONBounded(context.Background(), srv.URL, &p, opts); err != errJSONFetchNoLimit {
		t.Fatalf("缺限应返回 errJSONFetchNoLimit，得到 %v", err)
	}
}

func TestFetchJSONBoundedMalformedFatal(t *testing.T) {
	var hits int
	srv, opts := newJSONTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":`) // 截断的 JSON
	})
	defer srv.Close()
	var p jsonTestPayload
	err := fetchJSONBounded(context.Background(), srv.URL, &p, opts)
	if err == nil {
		t.Fatal("坏 JSON 应失败")
	}
	if hits != 1 {
		t.Fatalf("JSON 语法错误对同一 URL 不可重试，实际 %d 次", hits)
	}
}

func TestFetchJSONFromMirrorsFallback(t *testing.T) {
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer bad.Close()
	good := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":3,"name":"mirror2"}`)
	}))
	defer good.Close()

	// 两个 httptest 实例各有自己的测试 CA，取其一的 client 后在校验层
	// 放开证书（仅测试），专注验证"第一个源失败→回退第二个源"的逻辑。
	pool := bad.Client()
	pool.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

	opts := jsonTestOptions(1 << 20)
	opts.Client = pool
	opts.Attempts = 1
	var p jsonTestPayload
	if err := fetchJSONFromMirrors(context.Background(),
		[]string{bad.URL, good.URL}, &p, opts); err != nil {
		t.Fatalf("应回退到第二个镜像: %v", err)
	}
	if p.Name != "mirror2" {
		t.Fatalf("回退源数据错误: %+v", p)
	}
}

func TestFetchJSONFromMirrorsAllFail(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	opts := jsonTestOptions(1 << 20)
	opts.Client = srv.Client()
	opts.Attempts = 1
	var p jsonTestPayload
	err := fetchJSONFromMirrors(context.Background(), []string{srv.URL, srv.URL}, &p, opts)
	if err == nil || !strings.Contains(err.Error(), "全部 JSON 源") {
		t.Fatalf("全失败应返回汇总错误，得到 %v", err)
	}
}
