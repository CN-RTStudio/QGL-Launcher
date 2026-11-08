package main

import (
	"testing"
)

func pendingItem(savePath string, size int64) DownloadItem {
	return DownloadItem{SavePath: savePath, SizeBytes: size, Status: "pending"}
}

func TestGroupDownloadDiskDemandEmpty(t *testing.T) {
	if got := groupDownloadDiskDemand(nil); len(got) != 0 {
		t.Fatalf("空队列不应产生需求，实际 %d", len(got))
	}
}

func TestGroupDownloadDiskDemandOnlyPending(t *testing.T) {
	items := []DownloadItem{
		{SavePath: "/a", SizeBytes: 100, Status: "completed"},
		{SavePath: "/a", SizeBytes: 100, Status: "failed"},
		{SavePath: "/a", SizeBytes: 100, Status: "cancelled"},
		{SavePath: "/a", SizeBytes: 100, Status: "downloading"}, // 进行中仍占空间，但约定只预算 pending
	}
	got := groupDownloadDiskDemand(items)
	if len(got) != 0 {
		t.Fatalf("非 pending 条目不应入计划，实际 %d 组", len(got))
	}
}

func TestGroupDownloadDiskDemandGroupsByPath(t *testing.T) {
	items := []DownloadItem{
		pendingItem("/d1", 100),
		pendingItem("/d2", 50),
		pendingItem("/d1", 25),
		pendingItem("/d1", 0), // 未知
	}
	got := groupDownloadDiskDemand(items)
	if len(got) != 2 {
		t.Fatalf("应聚合成 2 个目录，实际 %d", len(got))
	}
	// 首次出现顺序必须稳定：/d1 在前。
	if got[0].Path != "/d1" || got[1].Path != "/d2" {
		t.Fatalf("目录顺序错误: %s, %s", got[0].Path, got[1].Path)
	}
	d1 := got[0]
	if d1.KnownBytes != 125 {
		t.Fatalf("/d1 已知字节应为 125，实际 %d", d1.KnownBytes)
	}
	if d1.UnknownItems != 1 {
		t.Fatalf("/d1 未知条目应为 1，实际 %d", d1.UnknownItems)
	}
	if d1.ItemCount != 3 {
		t.Fatalf("/d1 条目总数应为 3，实际 %d", d1.ItemCount)
	}
}

func TestGroupDownloadDiskDemandSkipsEmptyPath(t *testing.T) {
	// SavePath 为空（内部决定落盘目录的游戏本体等）无法判目录，跳过不报错。
	items := []DownloadItem{
		pendingItem("", 1 << 30),
		pendingItem("/known", 10),
	}
	got := groupDownloadDiskDemand(items)
	if len(got) != 1 || got[0].Path != "/known" {
		t.Fatalf("应只剩 /known 一组，实际 %+v", got)
	}
}

func TestGroupDownloadDiskDemandNegativeFoldsUnknown(t *testing.T) {
	// 负值按未知处理（声明无效，不计入已知字节）。
	items := []DownloadItem{
		{SavePath: "/d", SizeBytes: -999, Status: "pending"},
		pendingItem("/d", 10),
	}
	got := groupDownloadDiskDemand(items)
	if len(got) != 1 {
		t.Fatalf("应 1 组")
	}
	if got[0].KnownBytes != 10 || got[0].UnknownItems != 1 {
		t.Fatalf("负值折叠为未知后 known=10/unknown=1，实际 known=%d unknown=%d",
			got[0].KnownBytes, got[0].UnknownItems)
	}
}

// stubProbe 按 path 返回预设裁决，并记录每次被询问的参数。
type stubProbe struct {
	verdicts map[string]DiskFitAssessment
	calls    []struct {
		path     string
		req      int64
		inflight int64
	}
}

func (s *stubProbe) probe(path string, req, inflight int64) DiskFitAssessment {
	s.calls = append(s.calls, struct {
		path     string
		req      int64
		inflight int64
	}{path, req, inflight})
	if v, ok := s.verdicts[path]; ok {
		return v
	}
	return assessDiskFit(diskAvailUnknown, req, inflight)
}

func TestPlanDownloadDiskFitPassesAggregatedBytes(t *testing.T) {
	demands := []diskDirDemand{
		{Path: "/d1", KnownBytes: 300, ItemCount: 2},
		{Path: "/d2", KnownBytes: 700, ItemCount: 1},
	}
	sp := &stubProbe{verdicts: map[string]DiskFitAssessment{}}
	plans := planDownloadDiskFit(demands, sp.probe)
	if len(plans) != 2 || len(sp.calls) != 2 {
		t.Fatalf("应对每目录探测一次")
	}
	if sp.calls[0].path != "/d1" || sp.calls[0].req != 300 || sp.calls[0].inflight != 0 {
		t.Fatalf("/d1 探测参数错误: %+v", sp.calls[0])
	}
	if sp.calls[1].path != "/d2" || sp.calls[1].req != 700 {
		t.Fatalf("/d2 探测参数错误: %+v", sp.calls[1])
	}
}

func TestPlanDownloadDiskFitNilProbeIsUnknown(t *testing.T) {
	// probe 为 nil（极端防御）时不得 panic，全部给 unknown。
	plans := planDownloadDiskFit([]diskDirDemand{{Path: "/d", KnownBytes: 10}}, nil)
	if len(plans) != 1 || plans[0].Assessment.Verdict != diskFitUnknown {
		t.Fatalf("nil probe 应给 unknown，实际 %+v", plans)
	}
}

func TestBlockingDiskPlans(t *testing.T) {
	plans := []diskDirPlan{
		{Assessment: assessDiskFit(100*unitGiB, 1, 0)},             // ok
		{Assessment: assessDiskFit(diskAvailUnknown, 1, 0)},        // unknown
		{Assessment: assessDiskFit(0, diskReserveHeadroomBytes, 0)}, // short
		{Assessment: assessDiskFit(10, -1, 0)},                      // bad-input
	}
	blocked := blockingDiskPlans(plans)
	if len(blocked) != 2 {
		t.Fatalf("应只拦 short+bad-input 共 2 个，实际 %d", len(blocked))
	}
	for _, b := range blocked {
		if describeDiskPlanBlock(b) == "" {
			t.Fatal("阻止计划必须有非空说明")
		}
	}
}

func TestBlockingDiskPlansNoneWhenAllFit(t *testing.T) {
	plans := []diskDirPlan{
		{Assessment: assessDiskFit(100*unitGiB, 1*unitGiB, 0)},
		{Assessment: assessDiskFit(diskAvailUnknown, 5*unitGiB, 0)}, // unknown 不拦
	}
	if len(blockingDiskPlans(plans)) != 0 {
		t.Fatal("空间充足 / 探测失败时不应阻止")
	}
}

func TestEndToEndGroupPlanBlock(t *testing.T) {
	// 端到端：/short 目录需求超过给定余量 -> 被拦；/roomy 充足 -> 放行。
	items := []DownloadItem{
		pendingItem("/short", 10*unitGiB),
		pendingItem("/short", 10*unitGiB), // 合计 20GiB
		pendingItem("/roomy", 1*unitGiB),
	}
	demands := groupDownloadDiskDemand(items)
	sp := &stubProbe{verdicts: map[string]DiskFitAssessment{
		"/short":  assessDiskFit(5*unitGiB, 0, 0), // 该盘只剩 5GiB（已逼近水位）
		"/roomy":  assessDiskFit(100*unitGiB, 0, 0),
	}}
	plans := planDownloadDiskFit(demands, sp.probe)
	blocked := blockingDiskPlans(plans)
	if len(blocked) != 1 {
		t.Fatalf("应只有 /short 被拦，实际 %d 个", len(blocked))
	}
	if blocked[0].Demand.Path != "/short" {
		t.Fatalf("被拦目录应为 /short，实际 %s", blocked[0].Demand.Path)
	}
	if blocked[0].Demand.KnownBytes != 20*unitGiB {
		t.Fatalf("/short 聚合需求应为 20GiB，实际 %d", blocked[0].Demand.KnownBytes)
	}
}
