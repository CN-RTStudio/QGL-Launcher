package main

import (
	"strings"
	"testing"
)

func TestParseAssetIndexOK(t *testing.T) {
	raw := []byte(`{"objects":{"minecraft/lang/zh_cn.json":{"hash":"0123456789abcdef0123456789abcdef01234567","size":1234},"icon/16x16.png":{"hash":"ffffffffffffffffffffffffffffffffffffffff","size":99}},"totalSize":1333,"map_to_resources":false}`)
	vd := ParseAssetIndex(raw, defaultAssetIndexLimits())
	if !vd.OK {
		t.Fatalf("expected ok, got %s", vd.Reason)
	}
	if len(vd.Doc.Objects) != 2 {
		t.Fatalf("expected 2 objects, got %d", len(vd.Doc.Objects))
	}
	if vd.Doc.Objects[0].Name != "icon/16x16.png" {
		t.Fatalf("sort order wrong: %q", vd.Doc.Objects[0].Name)
	}
	if vd.Doc.TotalSize != 1333 {
		t.Fatalf("total wrong: %d", vd.Doc.TotalSize)
	}
}

func TestParseAssetIndexBadHash(t *testing.T) {
	cases := []string{
		`{"objects":{"a.json":{"hash":"short","size":1}}}`,
		`{"objects":{"a.json":{"hash":"0123456789abcdef0123456789abcdef0123456G","size":1}}}`,
		`{"objects":{"a.json":{"hash":"0123456789ABCDEF0123456789ABCDEF01234567","size":1}}}`,
	}
	for i, c := range cases {
		vd := ParseAssetIndex([]byte(c), defaultAssetIndexLimits())
		if vd.OK || vd.Reason != "asset-hash-format" {
			t.Fatalf("case %d: expected asset-hash-format, got ok=%v reason=%s", i, vd.OK, vd.Reason)
		}
	}
}

func TestParseAssetIndexNameTraversal(t *testing.T) {
	cases := []string{
		`{"objects":{"../evil.json":{"hash":"0123456789abcdef0123456789abcdef01234567","size":1}}}`,
		`{"objects":{"C:\\Windows\\x":{"hash":"0123456789abcdef0123456789abcdef01234567","size":1}}}`,
		`{"objects":{"..\\..\\boot":{"hash":"0123456789abcdef0123456789abcdef01234567","size":1}}}`,
		`{"objects":{"/etc/passwd":{"hash":"0123456789abcdef0123456789abcdef01234567","size":1}}}`,
	}
	for i, c := range cases {
		vd := ParseAssetIndex([]byte(c), defaultAssetIndexLimits())
		if vd.OK || vd.Reason != "asset-name-illegal" {
			t.Fatalf("case %d: expected asset-name-illegal, got ok=%v reason=%s", i, vd.OK, vd.Reason)
		}
	}
}

func TestParseAssetIndexSizeRange(t *testing.T) {
	raw := []byte(`{"objects":{"a.json":{"hash":"0123456789abcdef0123456789abcdef01234567","size":-5}}}`)
	vd := ParseAssetIndex(raw, defaultAssetIndexLimits())
	if vd.OK || vd.Reason != "asset-size-out-of-range" {
		t.Fatalf("expected asset-size-out-of-range, got ok=%v reason=%s", vd.OK, vd.Reason)
	}
}

func TestParseAssetIndexOverflow(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"objects":{`)
	for i := 0; i < 500000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"f` + itoaSafe(i) + `":{"hash":"0123456789abcdef0123456789abcdef01234567","size":1}`)
	}
	b.WriteString(`}}`)
	vd := ParseAssetIndex([]byte(b.String()), defaultAssetIndexLimits())
	if vd.OK || vd.Reason != "objects-overflow" {
		t.Fatalf("expected objects-overflow, got ok=%v reason=%s", vd.OK, vd.Reason)
	}
}

func TestPathCleanSlash(t *testing.T) {
	cases := map[string]string{
		"a/b/c":  "a/b/c",
		"a/../b": "b",
		"./a//b": "a/b",
		"../a":   "a",
	}
	for in, want := range cases {
		if got := pathCleanSlash(in); got != want {
			t.Fatalf("pathCleanSlash(%q)=%q want %q", in, got, want)
		}
	}
}
