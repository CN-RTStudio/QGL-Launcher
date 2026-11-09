package main

import (
	"math"
	"testing"
)

func TestNormalizeDeclaredSize(t *testing.T) {
	if v, ok := normalizeDeclaredSize(0); v != 0 || !ok {
		t.Fatal("0（未知）应合法")
	}
	if v, ok := normalizeDeclaredSize(1024); v != 1024 || !ok {
		t.Fatal("正大小应原样返回")
	}
	if _, ok := normalizeDeclaredSize(-1); ok {
		t.Fatal("负大小必须非法（未知只能用 0 表达）")
	}
}

func TestAssessQueueByteBudgetAllowsNormal(t *testing.T) {
	// 典型整合包：几十条、每条几十 MiB，远低于 1TiB。
	existing := make([]int64, 0, 40)
	for i := 0; i < 40; i++ {
		existing = append(existing, 40*unitMiB)
	}
	d := assessQueueByteBudget(existing, 80*unitMiB)
	if !d.OK {
		t.Fatalf("正常整合包应放行，实际 reason=%s", d.Reason)
	}
	if d.Projected != 40*40*unitMiB+80*unitMiB {
		t.Fatalf("Projected 计算错误: %d", d.Projected)
	}
}

func TestAssessQueueByteBudgetUnknownSizesCountAsZero(t *testing.T) {
	// 全部未知（0）+ 新条目未知：必须放行，不能因为没有 Content-Length 拒绝。
	d := assessQueueByteBudget([]int64{0, 0, 0}, 0)
	if !d.OK {
		t.Fatalf("未知大小应放行，实际 %s", d.Reason)
	}
	if d.Projected != 0 {
		t.Fatalf("未知项 Projected 应为 0，实际 %d", d.Projected)
	}
}

func TestAssessQueueByteBudgetRejectsNegativeIncoming(t *testing.T) {
	d := assessQueueByteBudget(nil, -1)
	if d.OK || d.Reason != byteBudgetNegative {
		t.Fatalf("负大小应 negative-size，实际 ok=%v reason=%s", d.OK, d.Reason)
	}
}

func TestAssessQueueByteBudgetRejectsOversizeItem(t *testing.T) {
	// 单条超过 512GiB 即拒，即使队列是空的。
	d := assessQueueByteBudget(nil, maxSingleDownloadDeclaredBytes+1)
	if d.OK || d.Reason != byteBudgetOversizeItem {
		t.Fatalf("超大单条应 item-too-large，实际 ok=%v reason=%s", d.OK, d.Reason)
	}
	// 恰好等于上限应放行。
	d2 := assessQueueByteBudget(nil, maxSingleDownloadDeclaredBytes)
	if !d2.OK {
		t.Fatalf("恰好 512GiB 应放行，实际 %s", d2.Reason)
	}
}

func TestAssessQueueByteBudgetRejectsAggregate(t *testing.T) {
	// 队列已声明 600GiB，再加入 500GiB，合计 1100GiB > 1TiB -> 拒绝。
	existing := []int64{600 * unitGiB}
	d := assessQueueByteBudget(existing, 500*unitGiB)
	if d.OK || d.Reason != byteBudgetOverBudget {
		t.Fatalf("聚合超 1TiB 应拒绝，实际 ok=%v reason=%s", d.OK, d.Reason)
	}
	if d.Headroom >= 0 {
		t.Fatalf("超预算时 Headroom 应为负（超出量），实际 %d", d.Headroom)
	}
	// 同样 1100GiB 但若新条目未知（0），队列本身只有 600GiB < 1TiB，应放行：
	// 未知大小不能算进聚合（否则会误杀）。
	d2 := assessQueueByteBudget(existing, 0)
	if !d2.OK {
		t.Fatalf("新条目未知时只算现有 600GiB，应放行，实际 %s", d2.Reason)
	}
}

func TestAssessQueueByteBudgetBoundary(t *testing.T) {
	// 合计恰好 1TiB 放行；再多 1 字节拒绝。
	d := assessQueueByteBudget([]int64{maxDownloadBudgetBytes - 1}, 1)
	if !d.OK {
		t.Fatalf("恰好上限应放行，实际 %s", d.Reason)
	}
	d2 := assessQueueByteBudget([]int64{maxDownloadBudgetBytes - 1}, 2)
	if d2.OK || d2.Reason != byteBudgetOverBudget {
		t.Fatalf("超上限 1 字节应拒绝，实际 ok=%v reason=%s", d2.OK, d2.Reason)
	}
}

func TestAssessQueueByteBudgetOverflow(t *testing.T) {
	// 现有之和溢出 int64。
	d := assessQueueByteBudget([]int64{math.MaxInt64, 1}, 0)
	if d.OK || d.Reason != byteBudgetOverflow {
		t.Fatalf("现有和溢出应 size-overflow，实际 ok=%v reason=%s", d.OK, d.Reason)
	}
	// 现有接近上限、新条目导致 projected 溢出。
	d2 := assessQueueByteBudget([]int64{math.MaxInt64 - 5}, 10)
	if d2.OK || d2.Reason != byteBudgetOverflow {
		t.Fatalf("projected 溢出应 size-overflow，实际 ok=%v reason=%s", d2.OK, d2.Reason)
	}
}

func TestDeclaredSizesFromQueue(t *testing.T) {
	if got := declaredSizesFromQueue(nil); got != nil {
		t.Fatalf("空队列应返回 nil，实际 %v", got)
	}
	list := []DownloadItem{
		{SizeBytes: 100},
		{SizeBytes: 0},   // 未知
		{SizeBytes: -5},  // 历史脏负值折叠成 0
		{SizeBytes: 200},
	}
	got := declaredSizesFromQueue(list)
	if len(got) != 4 {
		t.Fatalf("应保留每项占位，实际长度 %d", len(got))
	}
	// 负被折叠为 0，总和应是 300。
	sum, overflow := sumNonNegativeBytes(got)
	if overflow || sum != 300 {
		t.Fatalf("折叠后求和应为 300/无溢出，实际 %d/%v", sum, overflow)
	}
}

func TestMapByteBudgetToQueueReason(t *testing.T) {
	cases := map[byteBudgetReason]string{
		byteBudgetOK:           dqRejectNone,
		byteBudgetNegative:     dqRejectSizeNegative,
		byteBudgetOversizeItem: dqRejectItemTooLarge,
		byteBudgetOverflow:     dqRejectBudgetOverflow,
		byteBudgetOverBudget:   dqRejectAggregateBudget,
	}
	for in, want := range cases {
		if got := mapByteBudgetToQueueReason(in); got != want {
			t.Errorf("map(%s)=%s want %s", in, got, want)
		}
	}
}

func TestDescribeByteBudgetRejectNonEmpty(t *testing.T) {
	for _, r := range []byteBudgetReason{
		byteBudgetNegative, byteBudgetOversizeItem, byteBudgetOverflow, byteBudgetOverBudget,
	} {
		if describeByteBudgetReject(r) == "" {
			t.Errorf("原因 %s 必须有非空说明", r)
		}
	}
	if describeByteBudgetReject(byteBudgetOK) != "" {
		t.Error("OK 不应有拒绝说明")
	}
}
