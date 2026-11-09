package main

import (
	"context"
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

func TestSecureDownloadResultShape(t *testing.T) {
	r := secureDownloadResult{Bytes: 123, SHA256: "deadbeef", Attempts: 2}
	if fmt.Sprintf("%d/%s/%d", r.Bytes, r.SHA256, r.Attempts) != "123/deadbeef/2" {
		t.Fatal("secureDownloadResult 字段异常")
	}
}
