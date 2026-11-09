package main

// downloadledger_test.go —— 下载台账内核测试。
// 覆盖：字段收口（控制字符 / 限长 / 文件名剥路径）、去重追加、环形上限、
// 统计、哈希截断展示、状态白名单兜底。

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSanitizeLedgerEntry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	e := sanitizeLedgerEntry(downloadLedgerEntry{
		URL:        "https://launcher.mojang.com/v1/obj/ab12/\x1b[31mred",
		Host:       "launcher.mojang.com\x00evil",
		FileName:   "..\\..\\evil.dll\x1b",
		TotalBytes: 42,
		Status:     "",
		HashAlgo:   "SHA256",
		Hash:       "ABCDEF0123",
	}, now)
	if e.FileName != "evil.dll" {
		t.Fatalf("文件名应剥路径并去控制符: %q", e.FileName)
	}
	if strings.Contains(e.URL, "\x1b") || strings.Contains(e.URL, "[31m") {
		t.Fatalf("URL 控制字符未剥离: %q", e.URL)
	}
	if e.HashAlgo != "sha256" {
		t.Fatalf("哈希算法应小写: %q", e.HashAlgo)
	}
	if e.Hash != "abcdef0123" {
		t.Fatalf("哈希应小写: %q", e.Hash)
	}
	if e.Status != LedgerStatusFailed {
		t.Fatalf("空状态应兜底为 failed: %q", e.Status)
	}
	if e.StartedAt != now.Format(time.RFC3339) {
		t.Fatalf("空开始时间应补当前时间: %q", e.StartedAt)
	}
}

func TestLedgerFileNameOnly(t *testing.T) {
	cases := map[string]string{
		"mod.jar":          "mod.jar",
		"C:\\dir\\a.jar":   "a.jar",
		"/dir/sub/b.jar":   "b.jar",
		"..\\..\\..\\evil": "evil",
		"a/b\\c\\d.txt":    "d.txt",
	}
	for in, want := range cases {
		if got := ledgerFileNameOnly(in); got != want {
			t.Errorf("%q → %q, 期望 %q", in, got, want)
		}
	}
}

func TestLedgerAppendDedup(t *testing.T) {
	now := time.Now()
	e1 := downloadLedgerEntry{URL: "https://x/a", HashAlgo: "sha256", Hash: "h1", Status: LedgerStatusOK, StartedAt: now.Format(time.RFC3339)}
	e2 := downloadLedgerEntry{URL: "https://x/a", HashAlgo: "sha256", Hash: "h1", Status: LedgerStatusMismatch, StartedAt: now.Add(time.Minute).Format(time.RFC3339)}
	e3 := downloadLedgerEntry{URL: "https://y/b", HashAlgo: "none", Hash: "", Status: LedgerStatusSkipped, StartedAt: now.Format(time.RFC3339)}

	items := []downloadLedgerEntry{e1}
	items = ledgerAppend(items, e2) // 同 URL 同哈希：覆盖旧记录
	if len(items) != 1 {
		t.Fatalf("去重应保持 1 条, 实际 %d", len(items))
	}
	if items[0].Status != LedgerStatusMismatch {
		t.Fatalf("应保留最新状态: %q", items[0].Status)
	}
	items = ledgerAppend(items, e3)
	if len(items) != 2 {
		t.Fatalf("不同哈希应追加, 实际 %d", len(items))
	}
}

func TestLedgerAppendRingCap(t *testing.T) {
	now := time.Now()
	items := []downloadLedgerEntry{}
	for i := 0; i < maxDownloadLedgerEntries+20; i++ {
		e := downloadLedgerEntry{
			URL:      "https://x/" + strings.Repeat("a", i%3) + strconv.Itoa(i),
			HashAlgo: "sha256",
			Hash:     "h" + strconv.Itoa(i),
			Status:   LedgerStatusOK, StartedAt: now.Format(time.RFC3339),
		}
		items = ledgerAppend(items, e)
	}
	if len(items) != maxDownloadLedgerEntries {
		t.Fatalf("环形应保持 %d 条, 实际 %d", maxDownloadLedgerEntries, len(items))
	}
	// 新条目在尾部。
	last := items[len(items)-1]
	if last.Hash != "h"+strconv.Itoa(maxDownloadLedgerEntries+19) {
		t.Fatalf("尾部应是最新条目: %q", last.Hash)
	}
}

func TestLedgerSummary(t *testing.T) {
	items := []downloadLedgerEntry{
		{URL: "u1", Host: "a.com", Status: LedgerStatusOK},
		{URL: "u2", Host: "a.com", Status: LedgerStatusOK},
		{URL: "u3", Host: "b.com", Status: LedgerStatusMismatch},
		{URL: "u4", Host: "b.com", Status: LedgerStatusFailed},
		{URL: "u5", Host: "c.com", Status: LedgerStatusOversized},
		{URL: "u6", Host: "d.com", Status: LedgerStatusSkipped},
	}
	s := ledgerSummary(items)
	if s.Total != 6 || s.OK != 2 || s.Mismatch != 1 || s.Failed != 1 ||
		s.Oversized != 1 || s.Skipped != 1 || s.Hosts != 4 {
		t.Fatalf("统计不符: %+v", s)
	}
}

func TestLedgerTrimHash(t *testing.T) {
	if got := ledgerTrimHash("abcdef0123456789", 6); got != "abcdef…" {
		t.Fatalf("截断展示不符: %q", got)
	}
	if got := ledgerTrimHash("abc", 8); got != "abc" {
		t.Fatalf("短哈希不应截断: %q", got)
	}
}
