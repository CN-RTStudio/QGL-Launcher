package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestDecideReclaimCandidate(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	old := now.Add(-reclaimerMinAge - time.Hour)
	young := now.Add(-time.Hour)

	base := func() reclaimCandidateInput {
		return reclaimCandidateInput{
			Name:       "x.jar.tmp",
			WithinRoot: true,
			IsSymlink:  false,
			IsRegular:  true,
			Mtime:      old,
			Now:        now,
		}
	}

	// 正常旧 .tmp：纳入。
	if ok, kind, _ := decideReclaimCandidate(base()); !ok || kind != reclaimKindTemp {
		t.Errorf("旧 .tmp 应纳入 temp，got ok=%v kind=%v", ok, kind)
	}

	// 太新：跳过。
	in := base()
	in.Mtime = young
	if ok, _, reason := decideReclaimCandidate(in); ok || reason != reclaimSkipTooYoung {
		t.Errorf("在途文件应按 too-young 跳过，got ok=%v reason=%v", ok, reason)
	}

	// 符号链接：跳过。
	in = base()
	in.IsSymlink = true
	if ok, _, reason := decideReclaimCandidate(in); ok || reason != reclaimSkipSymlink {
		t.Errorf("符号链接应跳过，got ok=%v reason=%v", ok, reason)
	}

	// 越出根：跳过。
	in = base()
	in.WithinRoot = false
	if ok, _, reason := decideReclaimCandidate(in); ok || reason != reclaimSkipNotInRoot {
		t.Errorf("越界文件应跳过，got ok=%v reason=%v", ok, reason)
	}

	// 非普通文件：跳过。
	in = base()
	in.IsRegular = false
	if ok, _, reason := decideReclaimCandidate(in); ok || reason != reclaimSkipIrregular {
		t.Errorf("非常规文件应跳过，got ok=%v reason=%v", ok, reason)
	}

	// 不在白名单：跳过。
	in = base()
	in.Name = "notes.txt"
	if ok, _, reason := decideReclaimCandidate(in); ok || reason != reclaimSkipNotWhiteList {
		t.Errorf("非白名单文件应跳过，got ok=%v reason=%v", ok, reason)
	}

	// 孤儿侧车：基础文件不存在，纳入。
	in = base()
	in.Name = "a.jar.qglmeta"
	in.BaseExists = false
	if ok, kind, _ := decideReclaimCandidate(in); !ok || kind != reclaimKindOrphanMeta {
		t.Errorf("孤儿侧车应纳入 orphan-meta，got ok=%v kind=%v", ok, kind)
	}

	// 基础文件仍在：侧车必须保留。
	in = base()
	in.Name = "a.jar.qglmeta"
	in.BaseExists = true
	if ok, _, reason := decideReclaimCandidate(in); ok || reason != reclaimSkipMetaAlive {
		t.Errorf("有效侧车应跳过，got ok=%v reason=%v", ok, reason)
	}
}

func TestReclaimPlanEndToEnd(t *testing.T) {
	now := time.Now()
	old := now.Add(-reclaimerMinAge - time.Hour)
	young := now.Add(-time.Hour)

	root := t.TempDir()
	sub := filepath.Join(root, "versions")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	mk := func(rel string, size int, mtime time.Time) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, size)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// 应删除：旧 .tmp。
	mk("a.jar.tmp", 100, old)
	// 应删除：深层旧 .tmp。
	mk(filepath.Join("versions", "b.jar.tmp"), 50, old)
	// 应删除：孤儿侧车（无基础文件）。
	mk("c.jar.qglmeta", 10, old)
	// 应保留：侧车基础文件仍在。
	mk("d.jar", 200, old)
	mk("d.jar.qglmeta", 12, old)
	// 应保留：太新的 .tmp（在途）。
	mk("e.jar.tmp", 300, young)
	// 应保留：非白名单。
	mk("keep.txt", 1, old)
	// 应保留：符号链接（链接名虽为 .tmp，但回收器不跟随链接）。目标用非白名单名，
	// 保证“链接创建失败”的环境里目标自身也不会被当成残留回收而干扰计数。
	target := mk("real.dat", 40, old)
	if err := os.Symlink(target, filepath.Join(root, "link.tmp")); err != nil {
		// 某些环境（非管理员 / 未开开发者模式）无权建符号链接：清理目标并跳过该用例，
		// 符号链接跳过分支已由纯函数测试覆盖，不因此判失败。
		_ = os.Remove(target)
		t.Logf("无法创建符号链接，跳过链接用例: %v", err)
	}

	plan := BuildReclaimPlan([]string{root}, now)

	gotNames := map[string]bool{}
	var total int64
	for _, it := range plan.Items {
		gotNames[filepath.Base(it.Path)] = true
		total += it.Size
	}
	for _, want := range []string{"a.jar.tmp", "b.jar.tmp", "c.jar.qglmeta"} {
		if !gotNames[want] {
			t.Errorf("计划应包含 %s，实际 items=%v", want, gotNames)
		}
	}
	for _, keep := range []string{"d.jar.qglmeta", "e.jar.tmp", "keep.txt", "d.jar"} {
		if gotNames[keep] {
			t.Errorf("计划不应包含 %s", keep)
		}
	}
	if total != 160 {
		t.Errorf("计划回收字节应为 100+50+10=160，got %d", total)
	}

	// 跳过原因覆盖：在途文件应有 too-young 记录。
	hasYoung := false
	for _, s := range plan.Skipped {
		if filepath.Base(s.Path) == "e.jar.tmp" && s.Reason == reclaimSkipTooYoung {
			hasYoung = true
		}
	}
	if !hasYoung {
		t.Error("在途文件应出现在 skipped(too-young)")
	}

	report := executeReclaimPlan(plan)
	if report.Deleted != 3 {
		t.Errorf("应删除 3 个文件，got %d (failed=%v)", report.Deleted, report.Failed)
	}
	if report.Bytes != 160 {
		t.Errorf("回收字节应为 160，got %d", report.Bytes)
	}
	for _, gone := range []string{"a.jar.tmp", filepath.Join("versions", "b.jar.tmp"), "c.jar.qglmeta"} {
		if _, err := os.Lstat(filepath.Join(root, gone)); !os.IsNotExist(err) {
			t.Errorf("%s 应已删除", gone)
		}
	}
	for _, keep := range []string{"d.jar", "d.jar.qglmeta", "e.jar.tmp", "keep.txt"} {
		if _, err := os.Lstat(filepath.Join(root, keep)); err != nil {
			t.Errorf("%s 应保留，err=%v", keep, err)
		}
	}

	// 重复执行应为空操作（幂等）。
	plan2 := BuildReclaimPlan([]string{root}, now)
	if len(plan2.Items) != 0 {
		t.Errorf("二次扫描不应再有可回收项，got %d", len(plan2.Items))
	}
}

func TestReclaimDoesNotEscapeRoot(t *testing.T) {
	// 计划根之外的任何路径都不得被删除：手工构造一个 Items，执行闸应拦下。
	root := t.TempDir()
	outside := t.TempDir()
	victim := filepath.Join(outside, "x.jar.tmp")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := ReclaimPlan{
		Roots: []string{root},
		Items: []ReclaimItem{{Path: victim, Kind: reclaimKindTemp, Size: 1}},
	}
	report := executeReclaimPlan(plan)
	if report.Deleted != 0 || len(report.Failed) != 1 {
		t.Errorf("越界文件必须被执行闸拦下，deleted=%d failed=%d", report.Deleted, len(report.Failed))
	}
	if _, err := os.Lstat(victim); err != nil {
		t.Error("根外文件不应被删除")
	}
}
