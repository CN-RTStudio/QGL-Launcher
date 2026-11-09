package main

// modsaudit_report_test.go —— mods 审计报告渲染 / 导出测试。
//
// 报告内核是纯函数（modsaudit_report.go），直接在内存构造报告与基线测渲染与裁剪；
// 导出绑定（modsaudit_report_app.go）依赖 App 的 QGL 目录，只测纯内核部分，不启动
// Wails。裁剪、排序、无基线分支、detail 截断都覆盖。

import (
	"strings"
	"testing"
)

func TestClipReportDeltas(t *testing.T) {
	mk := func(n int) []ModAuditDelta {
		out := make([]ModAuditDelta, n)
		for i := range out {
			out[i] = ModAuditDelta{Dir: "d", RelPath: "f", Name: "f"}
		}
		return out
	}
	small, rest := clipReportDeltas(mk(5), 10)
	if len(small) != 5 || rest != 0 {
		t.Fatalf("小列表不应裁剪: got %d/%d", len(small), rest)
	}
	big, rest := clipReportDeltas(mk(300), 200)
	if len(big) != 200 || rest != 100 {
		t.Fatalf("大列表应裁剪到 200 并报告余量: got %d/%d", len(big), rest)
	}
}

func TestSortReportDeltas(t *testing.T) {
	in := []ModAuditDelta{
		{Dir: "mods", RelPath: "z.jar", Name: "z.jar"},
		{Dir: "mods", RelPath: "a.jar", Name: "a.jar"},
		{Dir: "b", RelPath: "m.jar", Name: "m.jar"},
	}
	sortReportDeltas(in)
	if in[0].Dir != "b" || in[1].RelPath != "a.jar" || in[2].RelPath != "z.jar" {
		t.Fatalf("排序结果不符: %+v", in)
	}
}

func TestClipDetail(t *testing.T) {
	s := strings.Repeat("x", 500)
	got := clipDetail(s)
	if len(got) > modAuditDetailMaxLen {
		t.Fatalf("detail 应被截断到上界内: %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("截断应以省略号结尾: %q", got[len(got)-6:])
	}
}

func TestBuildModAuditReportFileNoBaseline(t *testing.T) {
	r := ModAuditReport{
		Total: 3, Consistent: 1, Skipped: 0, LimitHit: false, HasRisks: true,
		Added: []ModAuditDelta{
			{Dir: "mods", RelPath: "new.jar", Name: "new.jar", Current: 10,
				Detail: "基线中没有该文件，来源未经验证"},
		},
		Tampered: []ModAuditDelta{
			{Dir: "mods", RelPath: "a.jar", Name: "a.jar", Baseline: 9, Current: 11,
				Detail: "文件体积或哈希与基线不一致，可能被改写"},
		},
	}
	f := buildModAuditReportFile(r, nil, "2026-10-11T00:00:00Z")
	if f.BaselineAt != "" {
		t.Fatalf("无基线时 baselineAt 应为空")
	}
	if f.TamperedCount != 1 || f.AddedCount != 1 || f.HasRisks != true {
		t.Fatalf("汇总字段不符: %+v", f)
	}
	if f.GeneratedAt != "2026-10-11T00:00:00Z" {
		t.Fatalf("生成时间未透传")
	}
	text := modAuditReportText(r, nil, "2026-10-11T00:00:00Z")
	if !strings.Contains(text, "篡改") || !strings.Contains(text, "新增") {
		t.Fatalf("文本报告缺少分节标题")
	}
	if !strings.Contains(text, "new.jar") || !strings.Contains(text, "a.jar") {
		t.Fatalf("文本报告缺少条目明细")
	}
	if !strings.Contains(text, "存在风险") {
		t.Fatalf("有风险报告应给出风险结论")
	}
}

func TestBuildModAuditReportFileWithBaseline(t *testing.T) {
	r := ModAuditReport{Total: 2, Consistent: 2, HasRisks: false}
	base := &ModAuditSnapshot{
		Version:   1,
		CreatedAt: "2026-09-01T00:00:00Z",
		Dirs:      []ModAuditDir{{Dir: "mods", Entries: []ModAuditEntry{}}},
	}
	f := buildModAuditReportFile(r, base, "now")
	if f.BaselineAt != "2026-09-01T00:00:00Z" || f.BaselineDirs != 1 {
		t.Fatalf("基线元信息未透传: %+v", f)
	}
	text := modAuditReportText(r, base, "now")
	if !strings.Contains(text, "未发现风险") {
		t.Fatalf("无风险报告应给出安全结论")
	}
	if !strings.Contains(text, "基线账本") {
		t.Fatalf("有基线时应打印基线时间")
	}
}

func TestModAuditReportTextBounded(t *testing.T) {
	// 大量差异条目时文本必须受 modAuditReportMaxLen 上界约束（本地 DoS 防护）。
	big := make([]ModAuditDelta, 0, 5000)
	for i := 0; i < 5000; i++ {
		big = append(big, ModAuditDelta{
			Dir: "mods", RelPath: strings.Repeat("f", 100) + ".jar",
			Name: "f.jar", Detail: strings.Repeat("d", 300),
		})
	}
	r := ModAuditReport{Total: 5000, HasRisks: true, Added: big, Tampered: big}
	text := modAuditReportText(r, nil, "now")
	if len(text) > modAuditReportMaxLen {
		t.Fatalf("报告超出长度上界: %d", len(text))
	}
	if !strings.Contains(text, "其余") {
		t.Fatalf("超限报告应折叠剩余条目")
	}
}
