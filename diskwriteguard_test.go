package main

import (
	"math"
	"testing"
)

func TestNewDiskWriteGuardUnknownDisables(t *testing.T) {
	g := newDiskWriteGuard(diskAvailUnknown, 0)
	if !g.Disabled() {
		t.Fatal("avail<0 必须停用守卫")
	}
	if g.Verdict() != diskFitUnknown {
		t.Fatalf("初始裁决应为 unknown，实际 %s", g.Verdict())
	}
	if g.Remaining() != diskAvailUnknown {
		t.Fatalf("停用态 Remaining 应为 -1，实际 %d", g.Remaining())
	}
}

func TestNewDiskWriteGuardDefaultHeadroom(t *testing.T) {
	g := newDiskWriteGuard(5<<30, -1)
	if g.headroom != diskReserveHeadroomBytes {
		t.Fatal("非正 headroom 应回退默认 1GiB 水位")
	}
}

func TestDiskWriteGuardUnknownAlwaysAllows(t *testing.T) {
	g := newDiskWriteGuard(diskAvailUnknown, 100)
	for i := 0; i < 50; i++ {
		ok, assess := g.recordChunk(1 << 20) // 每次 1MiB
		if !ok {
			t.Fatalf("第 %d 块不应被未知守卫拦截", i)
		}
		if assess.Verdict != diskFitUnknown {
			t.Fatalf("未知守卫裁决应恒为 unknown，实际 %s", assess.Verdict)
		}
	}
	if g.Written() != 50*(1<<20) {
		t.Fatalf("已写计数错误: %d", g.Written())
	}
}

func TestDiskWriteGuardAllowsUnderHeadroom(t *testing.T) {
	// 可用 100，水位 10，可写预算 90。
	g := newDiskWriteGuard(100, 10)
	for i := 0; i < 9; i++ {
		ok, assess := g.recordChunk(10)
		if !ok {
			t.Fatalf("第 %d 块（累计 %d）应允许", i, (i+1)*10)
		}
		if assess.Verdict != diskFitOK {
			t.Fatalf("应为 ok，实际 %s", assess.Verdict)
		}
	}
	if g.Written() != 90 {
		t.Fatalf("written=%d want 90", g.Written())
	}
	if r := g.Remaining(); r != 0 {
		t.Fatalf("打满预算后 Remaining=0，实际 %d", r)
	}
}

func TestDiskWriteGuardRejectsWhenHeadroomBreached(t *testing.T) {
	g := newDiskWriteGuard(100, 10)
	if ok, _ := g.recordChunk(90); !ok {
		t.Fatal("恰好用满预算 90 应允许")
	}
	// 再写哪怕 1 字节都会把可用压到水位 10 以下，必须拒绝该块（且不落盘）。
	ok, assess := g.recordChunk(1)
	if ok {
		t.Fatal("击穿水位的一块必须拒绝")
	}
	if assess.Verdict != diskFitShort {
		t.Fatalf("裁决应为 short，实际 %s", assess.Verdict)
	}
	if g.Verdict() != diskFitShort {
		t.Fatalf("守卫应记住 short，实际 %s", g.Verdict())
	}
	if g.Shortfall() <= 0 {
		t.Fatalf("short 时 Shortfall 应 >0，实际 %d", g.Shortfall())
	}
	// 被拒绝的一块不计入已写（在落盘前拦截）。
	if g.Written() != 90 {
		t.Fatalf("被拒块不应累加，written=%d want 90", g.Written())
	}
}

func TestDiskWriteGuardShortIsSticky(t *testing.T) {
	g := newDiskWriteGuard(50, 10) // 预算 40
	ok, _ := g.recordChunk(45)
	if ok {
		t.Fatal("写 45 超过预算 40，应直接 short")
	}
	// 之后即便给 0 字节的探测或更小的块，也应持续拒绝，不允许抖动放行。
	ok2, a2 := g.recordChunk(0)
	if ok2 || a2.Verdict != diskFitShort {
		t.Fatalf("short 后应持续拒绝，实际 ok=%v verdict=%s", ok2, a2.Verdict)
	}
}

func TestDiskWriteGuardNegativeChunkBadInput(t *testing.T) {
	g := newDiskWriteGuard(1<<30, 1<<20)
	ok, assess := g.recordChunk(-1)
	if ok {
		t.Fatal("负长度块必须拒绝")
	}
	if assess.Verdict != diskFitBadInput {
		t.Fatalf("应为 bad-input，实际 %s", assess.Verdict)
	}
	if g.Verdict() != diskFitBadInput {
		t.Fatalf("守卫应记住 bad-input，实际 %s", g.Verdict())
	}
}

func TestDiskWriteGuardOverflowBadInput(t *testing.T) {
	// 余量给到 int64 上限，使“能否落盘”不再是约束，单独压测累计溢出。
	g := newDiskWriteGuard(math.MaxInt64, 1<<10)
	big := int64(1) << 62
	if ok, _ := g.recordChunk(big); !ok {
		t.Fatal("首块 2^62 在近乎无限余量下应允许")
	}
	// 2^62 + 2^62 = 2^63，超过 MaxInt64(2^63-1)，addChecked 必须判溢出。
	ok, assess := g.recordChunk(big)
	if ok {
		t.Fatal("导致 int64 溢出的累计必须拒绝")
	}
	if assess.Verdict != diskFitBadInput {
		t.Fatalf("溢出应判 bad-input，实际 %s", assess.Verdict)
	}
	if g.Written() != big {
		t.Fatalf("溢出块不应推进 written，实际 %d want %d", g.Written(), big)
	}
}

func TestDiskWriteGuardRemaining(t *testing.T) {
	g := newDiskWriteGuard(1000, 200) // 预算 800
	if r := g.Remaining(); r != 800 {
		t.Fatalf("初始 Remaining=%d want 800", r)
	}
	g.recordChunk(300)
	if r := g.Remaining(); r != 500 {
		t.Fatalf("写 300 后 Remaining=%d want 500", r)
	}
	g.recordChunk(500)
	if r := g.Remaining(); r != 0 {
		t.Fatalf("写满预算 Remaining=%d want 0", r)
	}
}

func TestDiskWriteGuardRemainingZeroWhenDiskBelowHeadroom(t *testing.T) {
	// 磁盘本来就低于水位（avail<headroom），预算为负，Remaining 必须是 0 而不是负数。
	g := newDiskWriteGuard(5, 10)
	if r := g.Remaining(); r != 0 {
		t.Fatalf("低于水位时 Remaining 应为 0，实际 %d", r)
	}
}

func TestDiskWriteGuardChunkedUnknownSizeScenario(t *testing.T) {
	// 模拟 chunked：每块 32KiB，盘上只有 100KiB 余量、留 10KiB 水位（预算 90KiB）。
	const chunk = 32 * 1024
	g := newDiskWriteGuard(100*1024, 10*1024)
	allowed := 0
	for i := 0; i < 10; i++ {
		ok, _ := g.recordChunk(chunk)
		if !ok {
			break
		}
		allowed++
	}
	// 32*2=64K 允许；第三块 96K>90K 预算，应被拒。
	if allowed != 2 {
		t.Fatalf("应恰好允许 2 块，实际 %d", allowed)
	}
	if g.Written() != 2*chunk {
		t.Fatalf("已写应为 %d，实际 %d", 2*chunk, g.Written())
	}
}

func TestDiskWriteGuardAssessmentCarriesAfterWrite(t *testing.T) {
	g := newDiskWriteGuard(100, 10)
	_, assess := g.recordChunk(40)
	if assess.AfterWrite != 60 {
		t.Fatalf("AfterWrite=%d want 60", assess.AfterWrite)
	}
	if assess.Requested != 40 {
		t.Fatalf("Requested=%d want 40", assess.Requested)
	}
	if assess.Available != 100 {
		t.Fatalf("Available=%d want 100", assess.Available)
	}
}

func TestDescribeDiskWriteAbort(t *testing.T) {
	if s := describeDiskWriteAbort(nil); s != "" {
		t.Fatalf("nil 守卫应给空串，实际 %q", s)
	}
	okG := newDiskWriteGuard(1<<30, 0)
	if s := describeDiskWriteAbort(okG); s != "" {
		t.Fatalf("ok 守卫应给空串，实际 %q", s)
	}
	unkG := newDiskWriteGuard(diskAvailUnknown, 0)
	if s := describeDiskWriteAbort(unkG); s != "" {
		t.Fatalf("unknown 守卫应给空串，实际 %q", s)
	}
	shortG := newDiskWriteGuard(50, 10)
	shortG.recordChunk(100)
	if s := describeDiskWriteAbort(shortG); s == "" {
		t.Fatal("short 守卫必须给出非空中止说明")
	}
	badG := newDiskWriteGuard(1<<30, 0)
	badG.recordChunk(-1)
	if s := describeDiskWriteAbort(badG); s == "" {
		t.Fatal("bad-input 守卫必须给出非空中止说明")
	}
}
