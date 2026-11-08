package main

import (
	"strings"
	"testing"
)

func TestParseOptionsFile(t *testing.T) {
	lim := defaultInstanceCfgLimits()
	raw := "# comment\nwidth=800\nheight=600\nrenderDistance=12\n"
	vd := ParseOptionsFile([]byte(raw), lim)
	if !vd.OK {
		t.Fatalf("good options rejected: %s", vd.Reason)
	}
	if len(vd.Lines) != 3 {
		t.Fatalf("lines=%d want 3", len(vd.Lines))
	}
	if vd.Lines[0].Key != "width" || vd.Lines[0].Value != "800" {
		t.Fatalf("first line wrong: %+v", vd.Lines[0])
	}

	bad := []struct {
		name string
		in   string
		want string
	}{
		{"no-eq", "justAWord\n", "options-no-eq"},
		{"bad-key", "key with space=1\n", "options-key-illegal"},
		{"nul", "a=b\x00c\n", "options-nul"},
		{"ctrl", "a=b\x01c\n", "options-control"},
	}
	for _, c := range bad {
		vd := ParseOptionsFile([]byte(c.in), lim)
		if vd.OK || !strings.Contains(vd.Reason, c.want) {
			t.Fatalf("%s: ok=%v reason=%q", c.name, vd.OK, vd.Reason)
		}
	}
}

func TestParseOptionsControlStrip(t *testing.T) {
	lim := defaultInstanceCfgLimits()
	// 控制字符在值里被净化剔除，但非 \t 控制字符应导致整行被净化为可接受
	vd := ParseOptionsFile([]byte("key=val\x01ue\n"), lim)
	if vd.OK {
		t.Fatalf("control char accepted: %v", vd.Lines)
	}
}

func TestParseInstanceJSON(t *testing.T) {
	lim := defaultInstanceCfgLimits()
	good := `{"name":"\u0062eta World","version":"1.20.1","javaPath":"java/bin/java.exe","mcDir":"instances/beta"}`
	vd := ParseInstanceJSON([]byte(good), lim)
	if !vd.OK {
		t.Fatalf("good json rejected: %s", vd.Reason)
	}
	if vd.Doc.Name != "beta World" || vd.Doc.Version != "1.20.1" {
		t.Fatalf("doc wrong: %+v", vd.Doc)
	}

	bad := []struct {
		name string
		in   string
		want string
	}{
		{"parse", `{"name":`, "json-parse-fail"},
		{"java-dotdot", `{"javaPath":"../evil.exe"}`, "java-path:dotdot"},
		{"mc-dotdot", `{"mcDir":"../escape"}`, "mc-dir:dotdot"},
	}
	for _, c := range bad {
		vd := ParseInstanceJSON([]byte(c.in), lim)
		if vd.OK || !strings.Contains(vd.Reason, c.want) {
			t.Fatalf("%s: ok=%v reason=%q", c.name, vd.OK, vd.Reason)
		}
	}
}

func TestSanitizeInstanceText(t *testing.T) {
	if s := sanitizeInstanceText("a\x01b\x02c", 100); s != "abc" {
		t.Fatalf("strip wrong: %q", s)
	}
	if s := sanitizeInstanceText("abcdef", 3); s != "abc" {
		t.Fatalf("truncate wrong: %q", s)
	}
	if s := sanitizeInstanceText("a\tb", 100); s != "a\tb" {
		t.Fatalf("tab kept wrong: %q", s)
	}
}

func TestSummarizeInstanceVerdict(t *testing.T) {
	if s := SummarizeInstanceVerdict(instanceVerdict{OK: true, Doc: instanceDoc{Name: "x"}}); s != "instance ok lines=0 name=x" {
		t.Fatalf("summary wrong: %q", s)
	}
	if s := SummarizeInstanceVerdict(instanceVerdict{OK: false, Reason: "json-parse-fail"}); s != "instance bad json-parse-fail" {
		t.Fatalf("summary wrong: %q", s)
	}
}
