package main

// fabricguard_test.go —— Fabric 版本/URL 校验内核的测试。

import (
	"strings"
	"testing"
)

func TestValidateFabricVersionString(t *testing.T) {
	var lim0 FabricLimits
	lim := lim0.withDefaults()
	good := []string{
		"0.14.24",
		"1.19.4",
		"1.20",
		"1",
		"0.14.9-beta.1",
		"0.14.10-rc2",
		"23.12.0-alpha1",
		"1.19.4-pre1",
		"0.14.9-beta",
	}
	bad := []string{
		"",
		"   ",
		strings.Repeat("a", 100),
		"1.19.4\x00x",
		"1.19/4",
		"1.19\\4",
		"1..4",
		".1.4",
		"1.4.",
		"1.4.x",
		"a.b.c",
		"1.19.4-evil",
		"1.19.4-",
		"../../etc/passwd",
		"1.2.3.4.5.6.7.8.9",
	}
	for _, v := range good {
		if _, err := ValidateFabricVersionString(v, lim); err != nil {
			t.Errorf("version %q rejected: %v", v, err)
		}
	}
	for _, v := range bad {
		if _, err := ValidateFabricVersionString(v, lim); err == nil {
			t.Errorf("version %q accepted", v)
		}
	}
}

func TestCompareFabricVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.14.9", "0.14.10", -1},
		{"0.14.10", "0.14.9", 1},
		{"1.19.4", "1.19.4", 0},
		{"1.19", "1.19.0", 0},
		{"1.20", "1.19.4", 1},
		{"0.14.24", "0.15", -1},
		{"1.2.3", "1.2", 1},
	}
	for _, c := range cases {
		if got := CompareFabricVersions(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestValidateFabricMetaUrl(t *testing.T) {
	var lim0 FabricLimits
	lim := lim0.withDefaults()
	good := []string{
		"https://meta.fabricmc.net/v2/versions/loader/1.19.4",
		"https://maven.fabricmc.net/net/fabricmc/fabric-loader/0.14.24/fabric-loader-0.14.24.jar",
		"https://fabricmc.net/use/installer/",
		"https://meta.fabricmc.net/v2/versions/loader/1.20.1/0.15.11",
	}
	bad := []string{
		"",
		"http://meta.fabricmc.net/v2",            // 明文
		"https://evil.example/v2",                 // 非白名单
		"https://meta.fabricmc.net.evil.com/v2",   // 后缀欺骗
		"https://meta.fabricmc.net/v2\x00x",       // 控制字符
		strings.Repeat("https://meta.fabricmc.net/"+"a/", 20), // 过深路径
		"https://maven.fabricmc.net/..%2f..%2fetc", // 穿越（%2f 保留）
	}
	for _, u := range good {
		if _, err := ValidateFabricMetaUrl(u, lim); err != nil {
			t.Errorf("url %q rejected: %v", u, err)
		}
	}
	for _, u := range bad {
		if _, err := ValidateFabricMetaUrl(u, lim); err == nil {
			t.Errorf("url %q accepted", u)
		}
	}
}

func TestValidateFabricArtifactSegment(t *testing.T) {
	var lim0 FabricLimits
	lim := lim0.withDefaults()
	good := []string{"net", "fabricmc", "fabric-loader", "0.14.24", "1.19.4"}
	bad := []string{"", "a/b", "a\\b", "..", "../x", strings.Repeat("c", 300), "x\x00y"}
	for _, s := range good {
		if _, err := ValidateFabricArtifactSegment(s, lim); err != nil {
			t.Errorf("segment %q rejected: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := ValidateFabricArtifactSegment(s, lim); err == nil {
			t.Errorf("segment %q accepted", s)
		}
	}
}

func TestIsDottedNumber(t *testing.T) {
	good := []string{"1", "1.19", "0.14.24", "23.12.0", "1.02"}
	bad := []string{"", ".", "1.", ".1", "1..2", "1.a", "a", "1.2.3.4.5.6.7.8.9.0"}
	for _, s := range good {
		if !isDottedNumber(s) {
			t.Errorf("%q should be dotted number", s)
		}
	}
	for _, s := range bad {
		if isDottedNumber(s) {
			t.Errorf("%q should not be dotted number", s)
		}
	}
}

func TestSummarizeFabricError(t *testing.T) {
	if s := SummarizeFabricError(nil); s != "fabric check ok" {
		t.Errorf("unexpected ok summary: %s", s)
	}
	if s := SummarizeFabricError(errFabric("bad")); !strings.Contains(s, "rejected") {
		t.Errorf("unexpected err summary: %s", s)
	}
}

type errFabric string

func (e errFabric) Error() string { return string(e) }
