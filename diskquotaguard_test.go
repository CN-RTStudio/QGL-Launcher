package main

import "testing"

func newTestLedger() *DQLedger {
	l := NewDQLedger(100*1024*1024*1024, 2*1024*1024*1024)
	l.UpdateFree(10 * 1024 * 1024 * 1024)
	return l
}

func TestDQReserveAndRelease(t *testing.T) {
	l := newTestLedger()
	if ok, _ := l.Reserve("a", 1<<30, 0); !ok {
		t.Fatal("1GB reservation should be granted")
	}
	if l.Reserved() != 1<<30 {
		t.Fatalf("reserved wrong %d", l.Reserved())
	}
	if ok, _ := l.Release("a"); !ok {
		t.Fatal("release should succeed")
	}
	if l.Reserved() != 0 {
		t.Fatalf("reserved after release wrong %d", l.Reserved())
	}
}

func TestDQConcurrentOversell(t *testing.T) {
	l := newTestLedger()
	// 空闲 10GB、安全水位 2GB，可分配 8GB。前两个各 3.5GB 成功，第三个 3.5GB 超卖被拒
	threeAndHalf := int64(3<<30 + 512<<20)
	if ok, _ := l.Reserve("t1", threeAndHalf, 0); !ok {
		t.Fatal("t1 should be granted")
	}
	if ok, _ := l.Reserve("t2", threeAndHalf, 0); !ok {
		t.Fatal("t2 should be granted")
	}
	if ok, fs := l.Reserve("t3", threeAndHalf, 0); ok {
		t.Fatalf("t3 must be rejected for oversell: %v", fs)
	}
}

func TestDQSafetyReserve(t *testing.T) {
	l := NewDQLedger(100<<30, 5<<30)
	l.UpdateFree(6 << 30)
	// 可分配=6-reserved-5=1GB；申请 2GB 会击穿安全水位
	if ok, fs := l.Reserve("x", 2<<30, 0); ok {
		t.Fatalf("must not breach safety reserve: %v", fs)
	}
}

func TestDQDecompressionExpansion(t *testing.T) {
	l := newTestLedger()
	// 压缩 1GB + 解压膨胀 7GB = 需 8GB，恰好在水位内
	if ok, _ := l.Reserve("pack", 1<<30, 7<<30); !ok {
		t.Fatal("8GB total with expansion should be granted")
	}
	// 再申请任何正空间都应失败（可用已贴水位）
	if ok, _ := l.Reserve("more", 1, 0); ok {
		t.Fatal("nothing should remain after filling to reserve line")
	}
}

func TestDQNegative(t *testing.T) {
	l := newTestLedger()
	if ok, _ := l.Reserve("n", -1, 0); ok {
		t.Fatal("negative reservation rejected")
	}
}

func TestDQDuplicateID(t *testing.T) {
	l := newTestLedger()
	l.Reserve("dup", 1<<20, 0)
	if ok, _ := l.Reserve("dup", 1<<20, 0); ok {
		t.Fatal("duplicate reservation id must be rejected")
	}
}

func TestDQReleaseUnknown(t *testing.T) {
	l := newTestLedger()
	if ok, _ := l.Release("ghost"); ok {
		t.Fatal("releasing unknown id must fail")
	}
}

func TestDQAvailableClampsToZero(t *testing.T) {
	l := NewDQLedger(100<<30, 50<<30)
	l.UpdateFree(10 << 30)
	if l.Available() != 0 {
		t.Fatalf("available should clamp to 0, got %d", l.Available())
	}
}

func TestDQHoldCount(t *testing.T) {
	l := newTestLedger()
	l.Reserve("a", 1<<20, 0)
	l.Reserve("b", 1<<20, 0)
	if l.HoldCount() != 2 {
		t.Fatalf("hold count wrong %d", l.HoldCount())
	}
	l.Release("a")
	if l.HoldCount() != 1 {
		t.Fatalf("hold count after release wrong %d", l.HoldCount())
	}
}

func TestDQReflectsUpdatedFree(t *testing.T) {
	l := newTestLedger()
	l.Reserve("a", 1<<30, 0)
	// 磁盘被外部占用，空闲降到 3GB：可用=3-1-2=0，新申请必拒
	l.UpdateFree(3 << 30)
	if ok, _ := l.Reserve("b", 1<<20, 0); ok {
		t.Fatal("after free space dropped, new reservation must fail")
	}
}
