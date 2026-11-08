package main

import (
	"testing"
)

func TestNormalizeLang_Known(t *testing.T) {
	cases := map[string]string{
		"zh_CN": "zh_CN",
		"zh_cn": "zh_CN",
		"en_us": "en_US",
		"de":    "de",
	}
	for in, want := range cases {
		got, err := NormalizeLangTag(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Fatalf("%s = %s want %s", in, got, want)
		}
	}
}

func TestNormalizeLang_Reject(t *testing.T) {
	bad := []string{"", "  ", "zh/CN", "../../etc", "zh.CN", "en US", "a\nb", "x", "this-language-is-way-too-long"}
	for _, b := range bad {
		if _, err := NormalizeLangTag(b); err == nil {
			t.Fatalf("must reject %q", b)
		}
	}
}

func TestIsAcceptableLang(t *testing.T) {
	if !IsAcceptableLang("ja_JP") {
		t.Fatal("ja_JP should pass")
	}
	if IsAcceptableLang("../x") {
		t.Fatal("path traversal must fail")
	}
}
