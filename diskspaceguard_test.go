package main

import (
	"math"
	"testing"
)

func TestAddChecked(t *testing.T) {
	cases := []struct {
		name string
		a, b int64
		want int64
		ok   bool
	}{
		{"zero", 0, 0, 0, true},
		{"simple", 100, 200, 300, true},
		{"negative a", -1, 5, 0, false},
		{"negative b", 5, -1, 0, false},
		{"max boundary", math.MaxInt64 - 10, 10, math.MaxInt64, true},
		{"overflow", math.MaxInt64, 1, math.MaxInt64, false},
		{"overflow large", math.MaxInt64, math.MaxInt64, math.MaxInt64, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := addChecked(c.a, c.b)
			if ok != c.ok || got != c.want {
				t.Fatalf("addChecked(%d,%d)=(%d,%v) want (%d,%v)", c.a, c.b, got, ok, c.want, c.ok)
			}
		})
	}
}

func TestSumNonNegativeBytes(t *testing.T) {
	// 普通求和。
	if got, overflow := sumNonNegativeBytes([]int64{1, 2, 3, 4}); got != 10 || overflow {
		t.Fatalf("普通求和=%d,overflow=%v want 10,false", got, overflow)
	}
	// 空 / nil 都是 0。
	if got, overflow := sumNonNegativeBytes(nil); got != 0 || overflow {
		t.Fatalf("nil 求和=%d,overflow=%v", got, overflow)
	}
	// size<=0 表示未知，按 0 计入，不触发溢出。
	if got, overflow := sumNonNegativeBytes([]int64{-5, 0, -1, 7}); got != 7 || overflow {
		t.Fatalf("忽略非正后=%d,overflow=%v want 7,false", got, overflow)
	}
	// 溢出被识别。
	if _, overflow := sumNonNegativeBytes([]int64{math.MaxInt64, 1}); !overflow {
		t.Fatal("MaxInt64+1 必须报溢出")
	}
	// 多个大数累计越过 MaxInt64。
	if _, overflow := sumNonNegativeBytes([]int64{1 << 62, 1 << 62, 1 << 62, 1 << 62}); !overflow {
		t.Fatal("四个 2^62 必须报溢出")
	}
}

func TestNormalizeNonNegative(t *testing.T) {
	if v, ok := normalizeNonNegative(0); v != 0 || !ok {
		t.Fatal("0 应合法")
	}
	if v, ok := normalizeNonNegative(123); v != 123 || !ok {
		t.Fatal("正值应原样返回")
	}
	if _, ok := normalizeNonNegative(-1); ok {
		t.Fatal("负数必须非法")
	}
	if _, ok := normalizeNonNegative(math.MinInt64); ok {
		t.Fatal("MinInt64 必须非法")
	}
}

func TestAssessDiskFitUnknownWhenProbeFails(t *testing.T) {
	// available 为 -1（探测失败）时，无论申请多大都给 unknown，绝不能误杀。
	for _, avail := range []int64{-1, -100} {
		a := assessDiskFit(avail, 1<<40, 0)
		if a.Verdict != diskFitUnknown {
			t.Fatalf("avail=%d 应 unknown，实际 %s", avail, a.Verdict)
		}
	}
	// unknown 即使 requested 是天文数字也不判 short（没有证据不能拦）。
	a := assessDiskFit(diskAvailUnknown, math.MaxInt64, 0)
	if a.Verdict != diskFitUnknown {
		t.Fatalf("探测失败+超大申请仍应 unknown，实际 %s", a.Verdict)
	}
}

func TestAssessDiskFitBadInput(t *testing.T) {
	bad := []struct{ avail, req, inf int64 }{
		{1000, -1, 0},
		{1000, 0, -5},
		{1000, -1, -1},
	}
	for _, c := range bad {
		a := assessDiskFit(c.avail, c.req, c.inf)
		if a.Verdict != diskFitBadInput {
			t.Fatalf("(%d,%d,%d) 应 bad-input，实际 %s", c.avail, c.req, c.inf, a.Verdict)
		}
	}
}

func TestAssessDiskFitOK(t *testing.T) {
	// 100GiB 可用，申请 10GiB、在途 5GiB，远高于 1GiB 水位 -> ok。
	avail := int64(100) * unitGiB
	a := assessDiskFit(avail, 10*unitGiB, 5*unitGiB)
	if a.Verdict != diskFitOK {
		t.Fatalf("应 ok，实际 %s shortfall=%d", a.Verdict, a.Shortfall)
	}
	if a.Need != 15*unitGiB {
		t.Fatalf("Need=%d want 15GiB", a.Need)
	}
	if a.AfterWrite != 85*unitGiB {
		t.Fatalf("AfterWrite=%d want 85GiB", a.AfterWrite)
	}
}
