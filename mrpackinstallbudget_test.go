package main

import (
	"math"
	"testing"
)

func sizedMrpackFile(size int64) ModrinthModpackFile {
	return ModrinthModpackFile{
		Path:      "mods/x.jar",
		Downloads: []string{"https://x.example/a"},
		FileSize:  size,
	}
}

func TestSumMrpackSelectionBytesBasic(t *testing.T) {
	files := []ModrinthModpackFile{
		sizedMrpackFile(100),
		sizedMrpackFile(250),
		sizedMrpackFile(0), // 未知
		sizedMrpackFile(-5),
	}
	total, known, unknown, overflow := sumMrpackSelectionBytes(files, []int{0, 1, 2, 3})
	if total != 350 {
		t.Fatalf("total=%d want 350", total)
	}
	if known != 2 {
		t.Fatalf("known=%d want 2", known)
	}
	if unknown != 2 {
		t.Fatalf("unknown=%d want 2", unknown)
	}
	if overflow {
		t.Fatal("正常求和不应溢出")
	}
}

func TestSumMrpackSelectionBytesOnlySelected(t *testing.T) {
	// 未被选中的下标（服务器专用文件）不应计入客户端预算。
	files := []ModrinthModpackFile{
		sizedMrpackFile(100),
		sizedMrpackFile(9999),
		sizedMrpackFile(50),
	}
	total, known, unknown, _ := sumMrpackSelectionBytes(files, []int{0, 2})
	if total != 150 {
		t.Fatalf("只统计选中下标，total=%d want 150", total)
	}
	if known != 2 || unknown != 0 {
		t.Fatalf("known=%d unknown=%d", known, unknown)
	}
}

func TestSumMrpackSelectionBytesIgnoresBadIndex(t *testing.T) {
	files := []ModrinthModpackFile{sizedMrpackFile(10)}
	total, known, unknown, overflow := sumMrpackSelectionBytes(files, []int{-1, 0, 5, 99})
	if total != 10 {
		t.Fatalf("越界下标应忽略，total=%d want 10", total)
	}
	if known != 1 {
		t.Fatalf("known=%d want 1", known)
	}
	if unknown != 0 || overflow {
		t.Fatalf("unknown=%d overflow=%v", unknown, overflow)
	}
}

func TestSumMrpackSelectionBytesEmpty(t *testing.T) {
	total, known, unknown, overflow := sumMrpackSelectionBytes(nil, nil)
	if total != 0 || known != 0 || unknown != 0 || overflow {
		t.Fatalf("空选取应全零，total=%d known=%d unknown=%d overflow=%v",
			total, known, unknown, overflow)
	}
}

func TestSumMrpackSelectionBytesOverflow(t *testing.T) {
	files := []ModrinthModpackFile{
		sizedMrpackFile(math.MaxInt64),
		sizedMrpackFile(1),
	}
	total, _, _, overflow := sumMrpackSelectionBytes(files, []int{0, 1})
	if !overflow {
		t.Fatal("MaxInt64+1 必须判溢出")
	}
	if total != math.MaxInt64 {
		t.Fatalf("溢出时 total 应折叠到 MaxInt64，实际 %d", total)
	}
}

func TestAssessMrpackInstallBudgetOK(t *testing.T) {
	files := []ModrinthModpackFile{
		sizedMrpackFile(1 << 30), // 1GiB
		sizedMrpackFile(2 << 30), // 2GiB
		sizedMrpackFile(0),       // 未知，不阻断
	}
	a := assessMrpackInstallBudget(files, []int{0, 1, 2})
	if !a.OK() {
		t.Fatal("3GiB+未知应远低于 1TiB 预算，OK 应为 true")
	}
	if a.Total != 3<<30 {
		t.Fatalf("Total=%d want %d", a.Total, int64(3<<30))
	}
	if a.Count != 3 || a.KnownCount != 2 || a.UnknownCount != 1 {
		t.Fatalf("计数错误 %+v", a)
	}
	if a.OverBudget || a.Overflow {
		t.Fatalf("不应超预算/溢出 %+v", a)
	}
}

func TestAssessMrpackInstallBudgetBoundary(t *testing.T) {
	// 恰好等于预算：OK（严格大于才算超）。
	files := []ModrinthModpackFile{sizedMrpackFile(maxMrpackClientInstallBytes)}
	if a := assessMrpackInstallBudget(files, []int{0}); !a.OK() {
		t.Fatal("恰好等于预算应允许")
	}
	// 超出 1 字节：拒绝。
	files2 := []ModrinthModpackFile{sizedMrpackFile(maxMrpackClientInstallBytes + 1)}
	a2 := assessMrpackInstallBudget(files2, []int{0})
	if a2.OK() || !a2.OverBudget {
		t.Fatalf("超出 1 字节必须 OverBudget，%+v", a2)
	}
}

func TestAssessMrpackInstallBudgetOverBudget(t *testing.T) {
	// 拆成多个文件，每个都合法（远小于 8GiB 单文件上限），但总量超 1TiB。
	files := []ModrinthModpackFile{
		sizedMrpackFile(600 << 30), // ~600GiB
		sizedMrpackFile(600 << 30),
	}
	a := assessMrpackInstallBudget(files, []int{0, 1})
	if a.OK() {
		t.Fatal("约 1.2TiB 应超预算")
	}
	if !a.OverBudget || a.Overflow {
		t.Fatalf("应是 OverBudget 而非 Overflow %+v", a)
	}
	if s := describeMrpackInstallBudget(a); s == "" {
		t.Fatal("超预算必须给出非空说明")
	}
}

func TestAssessMrpackInstallBudgetOverflow(t *testing.T) {
	files := []ModrinthModpackFile{
		sizedMrpackFile(math.MaxInt64),
		sizedMrpackFile(math.MaxInt64),
	}
	a := assessMrpackInstallBudget(files, []int{0, 1})
	if a.OK() {
		t.Fatal("溢出必须不通过")
	}
	if !a.Overflow {
		t.Fatalf("应标记 Overflow %+v", a)
	}
	if s := describeMrpackInstallBudget(a); s == "" {
		t.Fatal("溢出必须给出非空说明")
	}
}

func TestAssessMrpackInstallBudgetUnknownNotBlocking(t *testing.T) {
	// 全部未知大小：Total=0 但 Count>0，预算仍 OK（实时磁盘守卫负责真实落盘）。
	files := []ModrinthModpackFile{
		sizedMrpackFile(0),
		sizedMrpackFile(0),
	}
	a := assessMrpackInstallBudget(files, []int{0, 1})
	if !a.OK() {
		t.Fatal("全未知不应被聚合预算拦截")
	}
	if a.UnknownCount != 2 || a.KnownCount != 0 || a.Total != 0 {
		t.Fatalf("计数错误 %+v", a)
	}
	if s := describeMrpackInstallBudget(a); s != "" {
		t.Fatalf("OK 时说明应为空，实际 %q", s)
	}
}
