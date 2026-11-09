package main

// secure_download_test.go 覆盖安全下载通道的全部关键分支：
// 正常下载 / sha256 流式校验 / 声明超限 / 分块传输实际超限 / 哈希不符 /
// 503 退避重试 / 404 不重试 / 拒绝明文 HTTP / 缺上限 / 进度回调 /
// 常量时间比较 / 残文件清理。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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

func TestStreamVerifiedDownloadNoRetryOn404(t *testing.T) {
	var hits int32
	srv, client := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	dest := secureDestPath(t, "missing.bin")

	_, err := streamVerifiedDownload(context.Background(), srv.URL, dest, secureDownloadOptions{
		MaxBytes: 4096,
		Attempts: 3,
		Client:   client,
	})
	if !errors.Is(err, errSecureDownloadStatus) {
		t.Fatalf("404 应返回 errSecureDownloadStatus，实际: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("404 为不可重试错误，应只请求 1 次，实际: %d", atomic.LoadInt32(&hits))
	}
}

func TestStreamVerifiedDownloadRejectsPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("明文 HTTP 服务器不应被请求")
	}))
	defer srv.Close()
	dest := secureDestPath(t, "plain.bin")

	_, err := streamVerifiedDownload(context.Background(), srv.URL, dest, secureDownloadOptions{
		MaxBytes: 4096,
		Attempts: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "非 HTTPS") {
		t.Fatalf("应拒绝明文 HTTP，实际: %v", err)
	}
}

func TestStreamVerifiedDownloadRequiresLimit(t *testing.T) {
	dest := secureDestPath(t, "nolimit.bin")
	_, err := streamVerifiedDownload(context.Background(), "https://example.com/x", dest,
		secureDownloadOptions{MaxBytes: 0, Attempts: 1})
	if !errors.Is(err, errSecureDownloadNoLimit) {
		t.Fatalf("缺少体积上限应返回 errSecureDownloadNoLimit，实际: %v", err)
	}
}

func TestStreamVerifiedDownloadProgress(t *testing.T) {
	body := []byte(strings.Repeat("p", secureDownloadBufSize*2+17))
	srv, client := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	dest := secureDestPath(t, "progress.bin")

	var lastReceived, reportedTotal int64
	var calls int
	_, err := streamVerifiedDownload(context.Background(), srv.URL, dest, secureDownloadOptions{
		MaxBytes: 16 << 20,
		Attempts: 1,
		Client:   client,
		Progress: func(received, total int64) {
			calls++
			lastReceived = received
			reportedTotal = total
		},
	})
	if err != nil {
		t.Fatalf("下载失败: %v", err)
	}
	if calls == 0 {
		t.Fatal("进度回调从未被触发")
	}
	if lastReceived != int64(len(body)) {
		t.Errorf("最终进度字节数不符: got %d want %d", lastReceived, len(body))
	}
	if reportedTotal != int64(len(body)) {
		t.Errorf("声明总大小不符: got %d want %d", reportedTotal, len(body))
	}
}

func TestStreamVerifiedDownloadContextCancel(t *testing.T) {
	srv, client := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 1000; i++ {
			// 客户端取消后写入会失败，服务端随之一轮轮结束。
			select {
			case <-r.Context().Done():
				return
			default:
			}
			_, _ = w.Write([]byte(strings.Repeat("z", 1024)))
			flusher.Flush()
			time.Sleep(2 * time.Millisecond)
		}
	}))
	dest := secureDestPath(t, "cancel.bin")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()
	_, err := streamVerifiedDownload(ctx, srv.URL, dest, secureDownloadOptions{
		MaxBytes: 64 << 20,
		Attempts: 1,
		Client:   client,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后应返回 context.Canceled，实际: %v", err)
	}
}

func TestConstantTimeEqualLowerHex(t *testing.T) {
	cases := []struct {
		name     string
		a, b     string
		expected bool
	}{
		{"相等", "abcdef0123456789", "abcdef0123456789", true},
		{"末位不同", "abcdef0123456789", "abcdef0123456780", false},
		{"首位不同", "abcdef0123456789", "0bcdef0123456789", false},
		{"长度不同", "abc", "abcdef", false},
		{"空串相等", "", "", true},
		{"大小写敏感", "AB", "ab", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := constantTimeEqualLowerHex(tc.a, tc.b); got != tc.expected {
				t.Errorf("constantTimeEqualLowerHex(%q,%q)=%v want %v",
					tc.a, tc.b, got, tc.expected)
			}
		})
	}
}

func TestStreamVerifiedDownloadRejectsSymlinkTarget(t *testing.T) {
	body := []byte("no-link-following")
	srv, client := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	dir := t.TempDir()
	link := filepath.Join(dir, "link.bin")
	target := filepath.Join(dir, "elsewhere.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("当前平台不支持创建符号链接: %v", err)
	}

	_, err := streamVerifiedDownload(context.Background(), srv.URL, link, secureDownloadOptions{
		MaxBytes: 4096,
		Attempts: 1,
		Client:   client,
	})
	if err == nil || !strings.Contains(err.Error(), "符号链接") {
		t.Fatalf("符号链接目标应被拒绝，实际: %v", err)
	}
	if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
		t.Fatalf("不应沿符号链接写到被指向路径，statErr=%v", statErr)
	}
}

// 结果结构体字段存在性的轻量自检：保证调用方能拿到字节数与 sha256。
func TestSecureDownloadResultShape(t *testing.T) {
	r := secureDownloadResult{Bytes: 123, SHA256: "deadbeef", Attempts: 2}
	if fmt.Sprintf("%d/%s/%d", r.Bytes, r.SHA256, r.Attempts) != "123/deadbeef/2" {
		t.Fatal("secureDownloadResult 字段异常")
	}
}
