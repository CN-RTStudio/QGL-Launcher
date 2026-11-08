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

func TestAssessDiskFitHeadroomBoundary(t *testing.T) {
	avail := diskReserveHeadroomBytes + 100
	// 申请 100 字节，写完恰好等于水位线，应放行（>= 水位即安全）。
	a := assessDiskFit(avail, 100, 0)
	if a.Verdict != diskFitOK {
		t.Fatalf("恰好水位应 ok，实际 %s shortfall=%d", a.Verdict, a.Shortfall)
	}
	// 再多申请 1 字节，击穿水位 -> short，缺口 1。
	b := assessDiskFit(avail, 101, 0)
	if b.Verdict != diskFitShort || b.Shortfall != 1 {
		t.Fatalf("越水位 1 字节应 short/shortfall=1，实际 %s/%d", b.Verdict, b.Shortfall)
	}
}

func TestAssessDiskFitAlreadyInsufficient(t *testing.T) {
	// 可用只有 500MiB（已低于 1GiB 水位），申请 0 也应判 short，
	// shortfall 至少要把盘补回到水位线（>=512MiB... 即 headroom-500MiB）。
	avail := int64(500) * unitMiB
	a := assessDiskFit(avail, 0, 0)
	if a.Verdict != diskFitShort {
		t.Fatalf("已低于水位应 short，实际 %s", a.Verdict)
	}
	want := diskReserveHeadroomBytes - int64(500)*unitMiB
	if a.Shortfall != want {
		t.Fatalf("Shortfall=%d want %d", a.Shortfall, want)
	}
}

func TestAssessDiskFitNeedExceedsAvailable(t *testing.T) {
	avail := int64(2) * unitGiB
	// 申请 10GiB：盘上根本不够，且击穿水位。缺口=10GiB-2GiB+1GiB 水位。
	a := assessDiskFit(avail, 10*unitGiB, 0)
	if a.Verdict != diskFitShort {
		t.Fatalf("应 short，实际 %s", a.Verdict)
	}
	want := int64(9) * unitGiB // (10-2)+1
	if a.Shortfall != want {
		t.Fatalf("Shortfall=%d want %d", a.Shortfall, want)
	}
	if a.AfterWrite >= 0 {
		t.Fatalf("AfterWrite 应为负表示透支，实际 %d", a.AfterWrite)
	}
}

func TestAssessDiskFitInflightReserved(t *testing.T) {
	avail := int64(3) * unitGiB
	// 当前申请 1GiB 单独看安全，但在途已排 2GiB：合计 3GiB，写完剩 0 < 水位 -> short。
	a := assessDiskFit(avail, 1*unitGiB, 2*unitGiB)
	if a.Verdict != diskFitShort {
		t.Fatalf("计入在途后应 short，实际 %s", a.Verdict)
	}
	// 若忽略在途只看本次，会误判 ok；这里显式锁定必须计入在途。
	if a.Need != 3*unitGiB {
		t.Fatalf("Need 必须含在途，实际 %d", a.Need)
	}
}

func TestAssessDiskFitNeedOverflow(t *testing.T) {
	// requested+inflight 越过 MaxInt64：物理上不可能，必须 bad-input 而不是回绕。
	a := assessDiskFit(math.MaxInt64, math.MaxInt64, math.MaxInt64)
	if a.Verdict != diskFitBadInput {
		t.Fatalf("Need 溢出应 bad-input，实际 %s", a.Verdict)
	}
}

func TestDescribeDiskFit(t *testing.T) {
	if s := describeDiskFit(assessDiskFit(100, 0, 0)); s != "" {
		t.Fatalf("short 以外应返回空说明，实际 %q", s)
	}
	short := assessDiskFit(0, diskReserveHeadroomBytes+1, 0)
	if describeDiskFit(short) == "" {
		t.Fatal("short 必须给出非空中文说明")
	}
	bad := assessDiskFit(10, -1, 0)
	if describeDiskFit(bad) == "" {
		t.Fatal("bad-input 必须给出非空说明")
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{-1, "未知"},
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1 KiB"},
		{1536, "1.5 KiB"},
		{unitMiB, "1 MiB"},
		{unitMiB + unitMiB/2, "1.5 MiB"},
		{unitGiB, "1 GiB"},
		{int64(2) * unitGiB, "2 GiB"},
		{unitTiB, "1 TiB"},
		{int64(3)*unitTiB + int64(3)*unitTiB/10, "3.3 TiB"},
	}
	for _, c := range cases {
		if got := FormatBytes(c.n); got != c.want {
			t.Errorf("FormatBytes(%d)=%q want %q", c.n, got, c.want)
		}
	}
}

func TestFormatBytesFractionRounding(t *testing.T) {
	// 余数很小也要至少显示 0.1，而不是四舍五入成整数误导。
	got := FormatBytes(unitKiB + 1)
	if got != "1.1 KiB" {
		t.Fatalf("最小小数应为 1.1 KiB，实际 %q", got)
	}
	// 不产生 "1.9"→"1.10" 之类的越界十分位。
	got2 := FormatBytes(unitMiB + unitMiB - unitKiB)
	if got2 != "1.9 MiB" {
		t.Fatalf("十分位封顶应为 1.9 MiB，实际 %q", got2)
	}
}
