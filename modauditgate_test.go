package main

// modauditgate_test.go —— 启动闸门决策内核的单元测试。决策纯函数不碰磁盘，
// 全部用例用构造的 ModAuditReport 直接断言口径。

import "testing"

func TestModAuditGateNoBaselineAllows(t *testing.T) {
	report := ModAuditReport{Total: 3, Added: []ModAuditDelta{{Name: "a.jar"}}}
	d := decideModAuditGate(report, false, false)
	if d.Kind != ModAuditGateAllow || d.Blocked {
		t.Fatalf("无基线应放行: %+v", d)
	}
	if d.HasBaseline {
		t.Fatalf("无基线时不应标记 HasBaseline=true: %+v", d)
	}
}

func TestModAuditGateConsistentAllows(t *testing.T) {
	report := ModAuditReport{Total: 5, Consistent: 5}
	d := decideModAuditGate(report, true, false)
	if d.Kind != ModAuditGateAllow || d.Blocked {
		t.Fatalf("一致应放行: %+v", d)
	}
}

func TestModAuditGateTamperedBlocksUnlessForce(t *testing.T) {
	report := ModAuditReport{
		Total:    2,
		Tampered: []ModAuditDelta{{Name: "evil.jar", Kind: "tampered"}},
	}
	d := decideModAuditGate(report, true, false)
	if d.Kind != ModAuditGateBlock || !d.Blocked {
		t.Fatalf("篡改且未强放应拦截: %+v", d)
	}
	if d.FirstTainted != "evil.jar" {
		t.Fatalf("应记录首个被篡改文件名: %q", d.FirstTainted)
	}

	d2 := decideModAuditGate(report, true, true)
	if d2.Kind != ModAuditGateAllowWarn || d2.Blocked || !d2.ForceUsed {
		t.Fatalf("篡改但强放应放行并标记: %+v", d2)
	}
}

func TestModAuditGateAddedMissingAllowWarn(t *testing.T) {
	added := ModAuditReport{Total: 4, Added: []ModAuditDelta{{Name: "new.jar", Kind: "added"}}}
	d := decideModAuditGate(added, true, false)
	if d.Kind != ModAuditGateAllowWarn || d.Blocked {
		t.Fatalf("仅新增应放行但提示: %+v", d)
	}
	missing := ModAuditReport{Total: 4, Missing: []ModAuditDelta{{Name: "gone.jar", Kind: "missing"}}}
	d2 := decideModAuditGate(missing, true, false)
	if d2.Kind != ModAuditGateAllowWarn || d2.Blocked {
		t.Fatalf("仅缺失应放行但提示: %+v", d2)
	}
}

func TestModAuditGateEventText(t *testing.T) {
	blocked := ModAuditGateDecision{
		Kind: ModAuditGateBlock, Blocked: true, HasBaseline: true, Tampered: 2, FirstTainted: "x.jar",
	}
	got := modAuditGateEventText(blocked)
	if len(got) == 0 || !containsSubstr(got, "拦截") || !containsSubstr(got, "x.jar") {
		t.Fatalf("拦截文案不合预期: %q", got)
	}
	force := ModAuditGateDecision{
		Kind: ModAuditGateAllowWarn, ForceUsed: true, HasBaseline: true, Tampered: 1, FirstTainted: "y.jar",
	}
	got2 := modAuditGateEventText(force)
	if !containsSubstr(got2, "强制放行") {
		t.Fatalf("强放文案不合预期: %q", got2)
	}
	warn := ModAuditGateDecision{Kind: ModAuditGateAllowWarn, HasBaseline: true, Added: 3, Missing: 1}
	got3 := modAuditGateEventText(warn)
	if !containsSubstr(got3, "新增 3") || !containsSubstr(got3, "缺失 1") {
		t.Fatalf("提示文案不合预期: %q", got3)
	}
	noBase := ModAuditGateDecision{Kind: ModAuditGateAllow, HasBaseline: false}
	got4 := modAuditGateEventText(noBase)
	if !containsSubstr(got4, "无基线") {
		t.Fatalf("无基线文案不合预期: %q", got4)
	}
}

func TestModAuditGateWarnReason(t *testing.T) {
	got := modAuditGateWarnReason(2, 0)
	if !containsSubstr(got, "新增 2") || containsSubstr(got, "缺失") {
		t.Fatalf("新增文案不合预期: %q", got)
	}
	got2 := modAuditGateWarnReason(0, 1)
	if !containsSubstr(got2, "缺失 1") {
		t.Fatalf("缺失文案不合预期: %q", got2)
	}
}
