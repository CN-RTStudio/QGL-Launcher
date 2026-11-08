package main

import (
	"reflect"
	"testing"
)

func TestResolveHeapSizesGBNormal(t *testing.T) {
	min, max, codes := ResolveHeapSizesGB(2, 4)
	if min != 2 || max != 4 || len(codes) != 0 {
		t.Fatalf("normal config altered: min=%d max=%d codes=%v", min, max, codes)
	}
}

func TestResolveHeapSizesGBZeroAndNegativeFallBack(t *testing.T) {
	min, max, codes := ResolveHeapSizesGB(0, 0)
	if min != defaultHeapMinGB || max != defaultHeapMaxGB {
		t.Fatalf("zero should fall back to %d/%d got %d/%d",
			defaultHeapMinGB, defaultHeapMaxGB, min, max)
	}
	if !reflect.DeepEqual(codes, []string{heapCodeMaxZeroDefault, heapCodeMinZeroDefault}) {
		t.Fatalf("unexpected codes for zero: %v", codes)
	}

	min, max, _ = ResolveHeapSizesGB(-8, -4)
	if min != defaultHeapMinGB || max != defaultHeapMaxGB {
		t.Fatalf("negative should fall back, got %d/%d", min, max)
	}
}

func TestResolveHeapSizesGBClampUpperBound(t *testing.T) {
	_, max, codes := ResolveHeapSizesGB(1, 1_000_000)
	if max != maxHeapGB {
		t.Fatalf("huge max should clamp to %d got %d", maxHeapGB, max)
	}
	found := false
	for _, c := range codes {
		if c == heapCodeMaxClamped {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %s in codes %v", heapCodeMaxClamped, codes)
	}
}

func TestResolveHeapSizesGBMinExceedsMax(t *testing.T) {
	// 用户填 min=16 但 max=8：min 必须被收敛到不超过 max。
	min, max, codes := ResolveHeapSizesGB(16, 8)
	if max != 8 || min != 8 {
		t.Fatalf("min>max should converge, got min=%d max=%d", min, max)
	}
	found := false
	for _, c := range codes {
		if c == heapCodeMinExceedsMax {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %s in codes %v", heapCodeMinExceedsMax, codes)
	}

	// max 被上界收敛到 1024，而 min 原值更大时，min 也应随之 <=max。
	min, max, _ = ResolveHeapSizesGB(5000, 5000)
	if min > max || max != maxHeapGB || min != maxHeapGB {
		t.Fatalf("after clamp min should equal bounded max, got min=%d max=%d", min, max)
	}
}

func TestResolveHeapSizesGBInvariant(t *testing.T) {
	// 穷举一批病态输入，断言恒有 1 <= min <= max <= maxHeapGB。
	inputs := [][2]int{
		{0, 0}, {-1, -1}, {1, 0}, {0, 1}, {999999, 1}, {1, 999999},
		{1025, 1024}, {1024, 1025}, {32, 32}, {1024, 1024},
	}
	for _, in := range inputs {
		min, max, _ := ResolveHeapSizesGB(in[0], in[1])
		if min < 1 || max < 1 || min > max || max > maxHeapGB {
			t.Fatalf("invariant broken for %v: min=%d max=%d", in, min, max)
		}
	}
}

func TestFormatHeapSizeGB(t *testing.T) {
	if got := FormatHeapSizeGB(2); got != "2G" {
		t.Fatalf("FormatHeapSizeGB(2)=%q want 2G", got)
	}
	if got := FormatHeapSizeGB(0); got != "2G" {
		t.Fatalf("FormatHeapSizeGB(0)=%q want fallback 2G", got)
	}
	if got := FormatHeapSizeGB(999999); got != "1024G" {
		t.Fatalf("FormatHeapSizeGB(huge)=%q want 1024G", got)
	}
}

func TestHeapGBToMB(t *testing.T) {
	if heapGBToMB(2) != 2048 {
		t.Fatal("2 GB should be 2048 MB")
	}
	if heapGBToMB(0) != 0 || heapGBToMB(-3) != 0 {
		t.Fatal("non-positive GB should map to 0 MB")
	}
	if heapGBToMB(maxHeapGB) != maxMemoryMBUpperBound {
		t.Fatal("maxHeapGB in MB must equal maxMemoryMBUpperBound")
	}
}

func TestBuildJVMHeapArgs(t *testing.T) {
	xms, xmx, minOut, maxOut, codes := BuildJVMHeapArgs(0, 0)
	if xms != "-Xms1G" || xmx != "-Xmx2G" || minOut != 1 || maxOut != 2 {
		t.Fatalf("default args wrong: %s %s %d %d", xms, xmx, minOut, maxOut)
	}
	if len(codes) != 2 {
		t.Fatalf("expected two default codes got %v", codes)
	}

	xms, xmx, _, _, _ = BuildJVMHeapArgs(16, 8)
	if xms != "-Xms8G" || xmx != "-Xmx8G" {
		t.Fatalf("min>max args should converge: %s %s", xms, xmx)
	}
}
