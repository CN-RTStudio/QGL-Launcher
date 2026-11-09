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
