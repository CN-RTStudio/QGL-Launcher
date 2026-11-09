package main

import (
	"testing"
)

func TestIsReclaimableTempName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"a.jar.tmp", true},
		{".native-ab12cd.tmp", true},
		{"1.20.1-server.jar.tmp", true},
		{"a.jar", false},
		{".tmp", false},
		{"tmp", false},
		{"a.tmp.bak", false},
		{"", false},
		{"a.TMP", false}, // 大小写敏感：只认精确 .tmp
	}
	for _, c := range cases {
		if got := isReclaimableTempName(c.name); got != c.want {
			t.Errorf("isReclaimableTempName(%q)=%v want %v", c.name, got, c.want)
		}
	}
	if !isNativeTempName(".native-xyz.tmp") {
		t.Error(".native-xyz.tmp 应被识别为 natives 临时文件")
	}
	if isNativeTempName("a.jar.tmp") {
		t.Error("普通下载临时文件不应被识别为 natives 临时文件")
	}
}

func TestIsReclaimableMetaName(t *testing.T) {
	if base, ok := isReclaimableMetaName("a.jar.qglmeta"); !ok || base != "a.jar" {
		t.Errorf("a.jar.qglmeta 解析异常 base=%q ok=%v", base, ok)
	}
	for _, bad := range []string{".qglmeta", "a.jar", "xqglmeta", ""} {
		if _, ok := isReclaimableMetaName(bad); ok {
			t.Errorf("%q 不应被当作侧车名", bad)
		}
	}
}

func TestStartsWithParentSegment(t *testing.T) {
	yes := []string{"../x", "../../y", "../a/b"}
	no := []string{"a/../b", "..x", "x", ".", "a/../../"}
	for _, p := range yes {
		if !startsWithParentSegment(p) {
			t.Errorf("%q 应以 ../ 开头", p)
		}
	}
	for _, p := range no {
		if startsWithParentSegment(p) {
			t.Errorf("%q 不应被判为父级逃逸", p)
		}
	}
}

func TestAssessReclaimBudget(t *testing.T) {
	if !assessReclaimBudget(0, 0, 100, reclaimerMaxBytes) {
		t.Error("空预算应允许纳入")
	}
	if assessReclaimBudget(reclaimerMaxFiles, 0, 1, reclaimerMaxBytes) {
		t.Error("达到文件数上限应拒绝")
	}
	if assessReclaimBudget(0, reclaimerMaxBytes-10, 100, reclaimerMaxBytes) {
		t.Error("纳入后超过字节上限应拒绝")
	}
	if !assessReclaimBudget(0, reclaimerMaxBytes-100, 100, reclaimerMaxBytes) {
		t.Error("恰好等于字节上限应允许")
	}
}
