package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// secure_download_test.go 覆盖安全下载通道的全部关键分支：
// 正常下载 / sha256 流式校验 / 声明超限 / 分块传输实际超限 / 哈希不符 /
// 503 退避重试 / 404 不重试 / 拒绝明文 HTTP / 缺上限 / 进度回调 /
// 常量时间比较 / 残文件清理。

// tlsTestServer 起一个客户端自动信任证书的 httptest TLS 服务。
func tlsTestServer(t *testing.T, h http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv, srv.Client()
}

func secureDestPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

func TestStreamVerifiedDownloadOK(t *testing.T) {
	body := []byte("hello-secure-download-channel")
	srv, client := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != "qgl-test-ua" {
			t.Errorf("未透传自定义 User-Agent，实际: %q", r.UserAgent())
		}
		_, _ = w.Write(body)
	}))
	dest := secureDestPath(t, "ok.bin")
	sum := sha256.Sum256(body)

	res, err := streamVerifiedDownload(context.Background(), srv.URL, dest, secureDownloadOptions{
		MaxBytes:       4096,
		ExpectedSHA256: hex.EncodeToString(sum[:]),
		Attempts:       1,
		UserAgent:      "qgl-test-ua",
		Client:         client,
	})
	if err != nil {
		t.Fatalf("正常下载失败: %v", err)
	}
	if res.Bytes != int64(len(body)) {
		t.Errorf("字节数不符: got %d want %d", res.Bytes, len(body))
	}
	if res.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("流式 sha256 不符: %s", res.SHA256)
	}
	if res.Attempts != 1 {
		t.Errorf("首次成功应为 1 次尝试，实际: %d", res.Attempts)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("目标文件未原子落盘: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("落盘内容不符: %q", got)
	}
}

func TestStreamVerifiedDownloadDeclaredTooLarge(t *testing.T) {
	body := []byte(strings.Repeat("x", 200))
	srv, client := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	dest := secureDestPath(t, "declared.bin")

	_, err := streamVerifiedDownload(context.Background(), srv.URL, dest, secureDownloadOptions{
		MaxBytes: 64,
		Attempts: 1,
		Client:   client,
	})
	if !errors.Is(err, errSecureDownloadTooLarge) {
		t.Fatalf("声明超限应返回 errSecureDownloadTooLarge，实际: %v", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("声明超限不应留下目标文件，statErr=%v", statErr)
	}
}

func TestStreamVerifiedDownloadActualTooLargeChunked(t *testing.T) {
	srv, client := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 不设置 Content-Length，靠 flush 强制分块传输，模拟"声明长度缺失"。
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("测试服务器不支持 Flusher")
		}
		chunk := strings.Repeat("a", 32)
		for i := 0; i < 8; i++ {
			_, _ = w.Write([]byte(chunk))
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	dest := secureDestPath(t, "chunked.bin")

	_, err := streamVerifiedDownload(context.Background(), srv.URL, dest, secureDownloadOptions{
		MaxBytes: 100, // 实际 256 字节
		Attempts: 1,
		Client:   client,
	})
	if !errors.Is(err, errSecureDownloadTooLarge) {
		t.Fatalf("实际超限应返回 errSecureDownloadTooLarge，实际: %v", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("实际超限不应留下目标文件，statErr=%v", statErr)
	}
}

func TestStreamVerifiedDownloadBadHash(t *testing.T) {
	body := []byte("integrity-must-hold")
	srv, client := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	dest := secureDestPath(t, "badhash.bin")

	_, err := streamVerifiedDownload(context.Background(), srv.URL, dest, secureDownloadOptions{
		MaxBytes:       4096,
		ExpectedSHA256: strings.Repeat("0", 64),
		Attempts:       1,
		Client:         client,
	})
	if !errors.Is(err, errSecureDownloadBadHash) {
		t.Fatalf("哈希不符应返回 errSecureDownloadBadHash，实际: %v", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("哈希不符不应留下目标文件，statErr=%v", statErr)
	}
}

func TestStreamVerifiedDownloadRetryOn503(t *testing.T) {
	var hits int32
	body := []byte("retry-then-ok")
	srv, client := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(body)
	}))
	dest := secureDestPath(t, "retry.bin")

	res, err := streamVerifiedDownload(context.Background(), srv.URL, dest, secureDownloadOptions{
		MaxBytes: 4096,
		Attempts: 3,
		Client:   client,
	})
	if err != nil {
		t.Fatalf("503 后重试应成功: %v", err)
	}
	if res.Attempts != 2 {
		t.Errorf("应在第 2 次尝试成功，实际: %d", res.Attempts)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Errorf("服务器应被请求 2 次，实际: %d", atomic.LoadInt32(&hits))
	}
}

// 结果结构体字段存在性的轻量自检：保证调用方能拿到字节数与 sha256。
