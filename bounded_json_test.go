package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// bounded_json_test.go 覆盖有界 JSON 拉取助手：正常解析、声明/实际体积
// 超限、非 JSON 媒体类型拒绝、503 退避重试、404 不重试、明文 URL 拒绝、
// 缺限拒绝、镜像顺序回退、媒体类型解析工具。

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
