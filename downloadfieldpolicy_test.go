package main

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testMinecraftDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return `C:\Users\tester\.minecraft`
	}
	return filepath.Join(string(filepath.Separator), "home", "tester", ".minecraft")
}

func testPathInMinecraft(t *testing.T, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{testMinecraftDir(t)}, parts...)...)
}

func TestAuditDownloadItemFieldsAccepts(t *testing.T) {
	mc := testMinecraftDir(t)
	cases := []DownloadItem{
		{ItemType: "game", CustomName: "1.20.1"},
		{ItemType: "loader", CustomName: "fabric 0.15.0 (1.20.1)"},
		{ItemType: "java", CustomName: "Java 21", JavaMajor: 21},
		{ItemType: "java", CustomName: "Java 8", JavaMajor: 8},
		{ItemType: "mod", CustomName: "Sodium.jar", SavePath: testPathInMinecraft(t, "mods")},
		{ItemType: "mod", CustomName: "Pack.zip"},
		{ItemType: "mod", CustomName: "Old.disabled"},
		{
			ItemType: "game+loader", CustomName: "forge 47.2.0 (1.20.1)",
			LoaderName: "forge", LoaderVersion: "47.2.0",
		},
		{
			ItemType: "game+loader", CustomName: "optifine HD_U (1.20.1)",
			LoaderName: "optifine", LoaderVersion: "HD_U", OptiFineType: "HD_U", OptiFinePatch: "I6",
		},
	}
	for _, item := range cases {
		if why := auditDownloadItemFields(item, mc); why != dfRejectNone {
			t.Fatalf("item %+v rejected: %s", item, why)
		}
	}
}

func TestAuditDownloadItemFieldsRejects(t *testing.T) {
	mc := testMinecraftDir(t)
	outside := filepath.Join(string(filepath.Separator), "tmp", "evil")
	cases := []struct {
		name string
		item DownloadItem
		want string
	}{
		{"save path outside", DownloadItem{ItemType: "mod", CustomName: "a.jar", SavePath: outside}, dfRejectSavePath},
		{"save path relative", DownloadItem{ItemType: "mod", CustomName: "a.jar", SavePath: "mods"}, dfRejectSavePath},
		{"save path not clean", DownloadItem{ItemType: "mod", CustomName: "a.jar", SavePath: testPathInMinecraft(t, "mods", "..", "..", "evil")}, dfRejectSavePath},
		{"save path control char", DownloadItem{ItemType: "mod", CustomName: "a.jar", SavePath: testPathInMinecraft(t) + "\x00x"}, dfRejectSavePath},
		{"save path too long", DownloadItem{ItemType: "mod", CustomName: "a.jar", SavePath: testPathInMinecraft(t, strings.Repeat("a", 1000))}, dfRejectSavePath},
		{"java major low", DownloadItem{ItemType: "java", CustomName: "Java 7", JavaMajor: 7}, dfRejectJavaMajor},
		{"java major high", DownloadItem{ItemType: "java", CustomName: "Java 100", JavaMajor: 100}, dfRejectJavaMajor},
		{"loader unknown", DownloadItem{ItemType: "game+loader", CustomName: "x", LoaderName: "evil", LoaderVersion: "1"}, dfRejectLoaderName},
		{"loader empty", DownloadItem{ItemType: "game+loader", CustomName: "x", LoaderName: "", LoaderVersion: "1"}, dfRejectLoaderName},
		{"loader version missing", DownloadItem{ItemType: "game+loader", CustomName: "x", LoaderName: "fabric", LoaderVersion: "  "}, dfRejectLoaderVersion},
		{"optifine type missing", DownloadItem{ItemType: "game+loader", CustomName: "x", LoaderName: "optifine", LoaderVersion: "HD_U", OptiFinePatch: "I6"}, dfRejectOptiFine},
		{"optifine patch missing", DownloadItem{ItemType: "game+loader", CustomName: "x", LoaderName: "optifine", LoaderVersion: "HD_U", OptiFineType: "HD_U"}, dfRejectOptiFine},
		{"mod exe", DownloadItem{ItemType: "mod", CustomName: "evil.exe"}, dfRejectModExt},
		{"mod no ext", DownloadItem{ItemType: "mod", CustomName: "evil"}, dfRejectModExt},
		{"mod double ext", DownloadItem{ItemType: "mod", CustomName: "a.jar.exe"}, dfRejectModExt},
	}
	for _, c := range cases {
		if why := auditDownloadItemFields(c.item, mc); why != c.want {
			t.Fatalf("%s: got %q want %q", c.name, why, c.want)
		}
	}
}

func TestAuditDownloadSavePathEmptyIsFine(t *testing.T) {
	if why := auditDownloadSavePath(DownloadItem{ItemType: "game"}, ""); why != dfRejectNone {
		t.Fatalf("empty save path rejected: %s", why)
	}
}

func TestDescribeDownloadFieldReject(t *testing.T) {
	codes := []string{
		dfRejectSavePath, dfRejectJavaMajor, dfRejectLoaderName,
		dfRejectLoaderVersion, dfRejectOptiFine, dfRejectModExt,
	}
	seen := map[string]bool{}
	for _, c := range codes {
		msg := describeDownloadFieldReject(c)
		if msg == "" {
			t.Fatalf("empty message for %s", c)
		}
		if seen[msg] {
			t.Fatalf("duplicate message for %s", c)
		}
		seen[msg] = true
	}
	if msg := describeDownloadFieldReject("unknown"); msg == "" {
		t.Fatal("fallback message is empty")
	}
}
