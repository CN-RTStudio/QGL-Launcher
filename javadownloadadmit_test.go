package main

import (
	"strings"
	"testing"
)

func javaCatalogForTest() []JavaDownloadInfo {
	return []JavaDownloadInfo{
		{
			MajorVer: 21,
			Name:     "Java 21 (LTS)",
			URL:      "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse",
			FileName: "OpenJDK21U-jdk_x64_windows_hotspot.zip",
			IsZip:    true,
		},
		{
			MajorVer: 17,
			Name:     "Java 17 (LTS)",
			URL:      "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jdk/hotspot/normal/eclipse",
			FileName: "OpenJDK17U-jdk_x64_windows_hotspot.zip",
			IsZip:    true,
		},
	}
}

func TestAuditJavaDownloadRequestAccepts(t *testing.T) {
	list := javaCatalogForTest()
	cases := []struct {
		major    int
		url      string
		filename string
	}{
		{21, "", "OpenJDK21U-jdk_x64_windows_hotspot.zip"},
		{21, list[0].URL, "OpenJDK21U-jdk_x64_windows_hotspot.zip"},
		{17, list[1].URL, "OpenJDK17U-jdk_x64_windows_hotspot.zip"},
	}
	for _, c := range cases {
		target, why := auditJavaDownloadRequest(c.major, c.url, list)
		if why != jdRejectNone {
			t.Fatalf("major=%d url=%q rejected: %s", c.major, c.url, why)
		}
		if target.FileName != c.filename {
			t.Fatalf("major=%d: got filename %q want %q", c.major, target.FileName, c.filename)
		}
	}
}

func TestAuditJavaDownloadRequestRejects(t *testing.T) {
	list := javaCatalogForTest()
	cases := []struct {
		name  string
		major int
		url   string
		want  string
	}{
		{"unknown major", 7, "", jdRejectUnknownMajor},
		{"negative major", -1, "", jdRejectUnknownMajor},
		{"file scheme", 21, "file:///C:/evil.msi", jdRejectURLMismatch},
		{"attacker host", 21, "https://evil.test/OpenJDK21U.zip", jdRejectURLMismatch},
		{"userinfo", 21, "https://user:pass@api.adoptium.net/x.zip", jdRejectURLMismatch},
		{"ip literal", 21, "https://127.0.0.1/x.zip", jdRejectURLMismatch},
		{"query append", 21, list[0].URL + "?x=1", jdRejectURLMismatch},
	}
	for _, c := range cases {
		_, why := auditJavaDownloadRequest(c.major, c.url, list)
		if why != c.want {
			t.Fatalf("%s: got %q want %q", c.name, why, c.want)
		}
	}
}

func TestAuditJavaArtifactName(t *testing.T) {
	good := []string{
		"OpenJDK21U-jdk_x64_windows_hotspot.zip",
		"jdk.msi",
		"jre.exe",
		"runtime.pkg",
		"bundle.dmg",
	}
	for _, n := range good {
		if why := auditJavaArtifactName(n); why != jdRejectNone {
			t.Fatalf("good name %q rejected: %s", n, why)
		}
	}
	bad := map[string]string{
		"":                                jdRejectBadName,
		"  ":                              jdRejectBadName,
		"a/b.zip":                         jdRejectBadName,
		`a\\b.zip`:                        jdRejectBadName,
		"x.zip:evil":                      jdRejectBadName,
		"..":                              jdRejectBadName,
		"..zip":                           jdRejectBadName,
		"evil.bat":                        jdRejectUnsafeArtifact,
		"evil.jar":                        jdRejectUnsafeArtifact,
		"evil":                            jdRejectUnsafeArtifact,
		"nul.zip":                         jdRejectBadName,
		strings.Repeat("a", 120) + ".zip": jdRejectBadName,
	}
	for n, want := range bad {
		if why := auditJavaArtifactName(n); why != want {
			t.Fatalf("bad name %q: got %q want %q", n, why, want)
		}
	}
}

func TestAuditJavaDownloadRequestArtifactShape(t *testing.T) {
	list := []JavaDownloadInfo{
		{MajorVer: 21, URL: "https://api.adoptium.net/x", FileName: "x.zip", IsZip: true, IsMSI: true},
		{MajorVer: 17, URL: "https://api.adoptium.net/y", FileName: "y.bat"},
		{MajorVer: 8, URL: "http://api.adoptium.net/z", FileName: "z.zip", IsZip: true},
		{MajorVer: 11, URL: "", FileName: "ok.zip", IsZip: true},
	}
	cases := []struct {
		major int
		want  string
	}{
		{21, jdRejectUnsafeArtifact},
		{17, jdRejectUnsafeArtifact},
		{8, jdRejectBadCatalogURL},
		{11, jdRejectBadCatalogURL},
	}
	for _, c := range cases {
		if _, why := auditJavaDownloadRequest(c.major, "", list); why != c.want {
			t.Fatalf("major=%d: got %q want %q", c.major, why, c.want)
		}
	}
}

func TestDescribeJavaDownloadReject(t *testing.T) {
	codes := []string{jdRejectUnknownMajor, jdRejectBadName, jdRejectBadCatalogURL, jdRejectURLMismatch, jdRejectUnsafeArtifact}
	seen := map[string]bool{}
	for _, c := range codes {
		msg := describeJavaDownloadReject(c)
		if msg == "" {
			t.Fatalf("empty message for %s", c)
		}
		if seen[msg] {
			t.Fatalf("duplicate message for %s", c)
		}
		seen[msg] = true
	}
	if msg := describeJavaDownloadReject("other-code"); msg == "" {
		t.Fatal("fallback message is empty")
	}
}
