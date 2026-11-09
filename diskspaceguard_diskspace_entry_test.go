package main

import (
	"math"
	"testing"
)

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
