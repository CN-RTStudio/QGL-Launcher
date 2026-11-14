package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigSnapshotChanged(t *testing.T) {
	base := configSnapshot{JavaPath: `C:\Java\bin\java.exe`, MaxMemMB: 4096, GameDir: `D:\mc`, VersionID: "1.20.4", AuthTypeLabel: "offline"}
	cur := configSnapshot{JavaPath: `c:\java\bin\java.exe`, MaxMemMB: 4096, GameDir: `D:\mc\`, VersionID: "1.20.4", AuthTypeLabel: "offline"}
	d := configSnapshotChanged(base, cur)
	if d.Changed {
		t.Fatalf("仅大小写/尾分隔符差异不应判为篡改: %+v", d.Fields)
	}
	cur.JavaPath = `C:\Temp\evil.exe`
	d = configSnapshotChanged(base, cur)
	if !d.Changed || len(d.Fields) != 1 || d.Fields[0] != "Java 路径" {
		t.Fatalf("Java 路径变化应命中: %+v", d)
	}
	cur.JavaPath = base.JavaPath
	cur.VersionID = "1.21"
	cur.MaxMemMB = 8192
	d = configSnapshotChanged(base, cur)
	if !d.Changed || len(d.Fields) != 2 {
		t.Fatalf("多字段变化应全部列出: %+v", d.Fields)
	}
}

func TestConfigSnapshotEqualAndDiffsText(t *testing.T) {
	a := configSnapshot{JavaPath: `C:\A`, MaxMemMB: 1, GameDir: `C:\G`, VersionID: "v", AuthTypeLabel: "offline"}
	b := configSnapshot{JavaPath: `c:\a\`, MaxMemMB: 1, GameDir: `C:\g`, VersionID: "v", AuthTypeLabel: "offline"}
	if !configSnapshotEqual(a, b) {
		t.Fatal("归一化后应相等")
	}
	text := configSnapshotDiffsText([]string{"Java 路径", "版本选择"})
	if text == "" || text != "关键配置被外部篡改: Java 路径、版本选择" {
		t.Fatalf("差异文本不符: %q", text)
	}
	if configSnapshotDiffsText(nil) != "" {
		t.Fatal("空差异应返回空串")
	}
}

func TestConfigSnapshotSanitize(t *testing.T) {
	s := configSnapshotSanitize(configSnapshot{
		JavaPath:      "C:\\x00evil\\bin\\java.exe\u0001\u0002",
		MaxMemMB:      -5,
		GameDir:       "C:\\x00game",
		VersionID:     "1.20.4\u0000",
		AuthTypeLabel: "external",
	})
	if s.JavaPath == "" || s.VersionID != "1.20.4" {
		t.Fatalf("控制字符应被剥离: %q %q", s.JavaPath, s.VersionID)
	}
}

func TestConfigSnapshotBaselineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")
	s := configSnapshot{JavaPath: `C:\Java\bin\java.exe`, MaxMemMB: 4096, GameDir: `D:\mc`, VersionID: "1.20.4", AuthTypeLabel: "offline"}
	writePrivateJSONBounded(path, s, configGuardMaxBytes)
	got := loadConfigSnapshotFile(path)
	if got.JavaPath != s.JavaPath || got.VersionID != s.VersionID {
		t.Fatalf("基线往返不一致: %+v vs %+v", got, s)
	}
	// 损坏文件 → 无基线（不 panic）。
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{not json"), 0600)
	if got := loadConfigSnapshotFile(bad); got.JavaPath != "" {
		t.Fatalf("损坏基线应按空处理: %+v", got)
	}
}

func TestConfigSnapshotGuardFlow(t *testing.T) {
	// 纯函数链路走查：外部改 Java 路径 → 变化命中；本进程可信写入刷新基线
	// （基线=当前值）后 → 不再触发。
	base := configSnapshot{JavaPath: `C:\Java\bin\java.exe`, MaxMemMB: 4096, GameDir: `D:\mc`, VersionID: "1.20.4", AuthTypeLabel: "offline"}
	evil := base
	evil.JavaPath = `C:\Temp\evil.exe`
	d := configSnapshotChanged(base, evil)
	if !d.Changed {
		t.Fatal("evil 应触发变化")
	}
	trusted := evil // 用户 UI 主动改（经 SaveGlobalConfig 刷新基线后）不再触发
	if d2 := configSnapshotChanged(evil, trusted); d2.Changed {
		t.Fatal("刷新后的配置不应再触发变化")
	}
}
