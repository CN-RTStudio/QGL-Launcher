package main

// launchsnapshot_test.go —— 启动参数快照纯函数与持久化的定向测试。
//
// 覆盖：字段收口（控制字符 / 长度）、环形保留、倒序排序、脏数据整体丢弃、
// 持久化往返。不跑全量 go test（本环境全量会挂在既有 TLS 用例上）。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildLaunchSnapshotSanitizesFields(t *testing.T) {
	snap := buildLaunchSnapshot(
		"v\u00011.21\u0007",                       // 版本 ID 带控制字符
		"C:\\Program Files\\Java\\jdk-21\u0000",   // 路径带 NUL
		"21.0.3\nLTS",                             // 版本号带换行
		"microsoft\u0001oauth",                    // auth 类型带控制字符
		4096, 12, true, false, 0,
	)
	if snap.VersionID != "v1.21" {
		t.Errorf("VersionID 未去控制字符: %q", snap.VersionID)
	}
	if snap.JavaPath != "C:\\Program Files\\Java\\jdk-21" {
		t.Errorf("JavaPath 未去 NUL: %q", snap.JavaPath)
	}
	if snap.JavaVersion != "21.0.3LTS" {
		t.Errorf("JavaVersion 未去换行: %q", snap.JavaVersion)
	}
	if snap.AuthType != "microsoftoauth" {
		t.Errorf("AuthType 未去控制字符: %q", snap.AuthType)
	}
	if snap.MaxMemMB != 4096 || snap.ModsCount != 12 || !snap.OnlineMode {
		t.Errorf("数值字段被误改: %+v", snap)
	}
}

func TestBuildLaunchSnapshotTruncatesLongFields(t *testing.T) {
	// 生成 2048 字节长路径（含空格，验证截断发生在收口之后）。
	long := strings.Repeat("a", 2048)
	_ = long
	snap := buildLaunchSnapshot("x", long, "1.0", "offline", 0, 0, false, false, 0)
	if len(snap.JavaPath) > maxSnapshotFieldLen {
		t.Errorf("JavaPath 未截断: %d > %d", len(snap.JavaPath), maxSnapshotFieldLen)
	}
	if snap.JavaPath == "" {
		t.Errorf("截断后不应为空（截断的是长串）")
	}
}

func TestDecideSnapshotRetentionKeepsNewest(t *testing.T) {
	base := make([]LaunchSnapshot, 0, 5)
	for i := 0; i < 5; i++ {
		base = append(base, LaunchSnapshot{VersionID: "old", CreatedAt: "2026-01-01T00:00:0" + string(rune('0'+i)) + "Z"})
	}
	next := LaunchSnapshot{VersionID: "new", CreatedAt: "2026-02-01T00:00:00Z"}
	out := decideSnapshotRetention(base, next, 3)
	if len(out) != 3 {
		t.Fatalf("环形保留长度错误: %d", len(out))
	}
	if out[len(out)-1].VersionID != "new" {
		t.Errorf("最新快照未保留在末尾: %+v", out)
	}
	// 入参不被修改（纯函数约定）
	if len(base) != 5 {
		t.Errorf("入参被修改: %d", len(base))
	}
}

func TestSortSnapshotsNewestFirst(t *testing.T) {
	items := []LaunchSnapshot{
		{VersionID: "a", CreatedAt: "2026-01-01T00:00:00Z"},
		{VersionID: "c", CreatedAt: "2026-03-01T00:00:00Z"},
		{VersionID: "b", CreatedAt: "2026-02-01T00:00:00Z"},
	}
	sortSnapshotsNewestFirst(items)
	if items[0].VersionID != "c" || items[2].VersionID != "a" {
		t.Errorf("倒序排序失败: %+v", items)
	}
}

func TestLoadLaunchSnapshotsDropsDirty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, launchSnapshotFileName)
	// 直接写一个含脏条目的文件（绕过 safeio，模拟不可信磁盘内容）
	dirty := []LaunchSnapshot{
		{VersionID: "good", CreatedAt: "2026-03-01T00:00:00Z"},
		{VersionID: "", CreatedAt: "2026-02-01T00:00:00Z"}, // 缺 VersionID → 丢弃
		{VersionID: "no-date", CreatedAt: ""},              // 缺 CreatedAt → 丢弃
	}
	if err := writePrivateJSONBounded(path, dirty, launchSnapshotMaxReadBytes); err != nil {
		t.Fatalf("写测试文件失败: %v", err)
	}
	items := loadLaunchSnapshots(path)
	if len(items) != 1 || items[0].VersionID != "good" {
		t.Errorf("脏条目未被丢弃: %+v", items)
	}
}

func TestLaunchSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := launchSnapshotFilePath(dir)
	// 不存在时返回空
	if items := loadLaunchSnapshots(path); len(items) != 0 {
		t.Errorf("空文件应返回空: %+v", items)
	}
	snap := buildLaunchSnapshot("1.21.4", "/opt/java/21", "21.0.3", "mojang", 4096, 8, true, false, 0)
	saveLaunchSnapshots(path, []LaunchSnapshot{snap})
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("快照文件未落盘: %v", err)
	}
	got := loadLaunchSnapshots(path)
	if len(got) != 1 || got[0].VersionID != "1.21.4" || got[0].ModsCount != 8 {
		t.Errorf("往返失败: %+v", got)
	}
}
