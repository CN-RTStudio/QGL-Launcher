package main

import (
	"fmt"
)

// ModAuditGateKind 是启动闸门的最终结论分类。
type ModAuditGateKind string

const (
	ModAuditGateAllow     ModAuditGateKind = "allow"      // 放行（含无基线 / 仅有提示）
	ModAuditGateBlock     ModAuditGateKind = "block"      // 拦截（存在未放行的篡改）
	ModAuditGateAllowWarn ModAuditGateKind = "allow-warn" // 放行但提示（新增 / 缺失）
)

// ModAuditGateDecision 是一次启动预检的决策结果，供前端预检页与审计事件消费。
type ModAuditGateDecision struct {
	Kind         ModAuditGateKind `json:"kind"`
	Blocked      bool             `json:"blocked"`
	ForceUsed    bool             `json:"forceUsed"`
	Tampered     int              `json:"tampered"`
	Added        int              `json:"added"`
	Missing      int              `json:"missing"`
	Consistent   int              `json:"consistent"`
	HasBaseline  bool             `json:"hasBaseline"`
	FirstTainted string           `json:"firstTainted,omitempty"` // 首个被篡改文件名
	Reason       string           `json:"reason,omitempty"`
}

// decideModAuditGate 把一次对账报告翻译成启动闸门决策。report 可为零值（无基线
// 时 current 全量 added）；hasBaseline 区分“首次审计”与“有基线但对账全新增”。
func decideModAuditGate(report ModAuditReport, hasBaseline bool, force bool) ModAuditGateDecision {
	d := ModAuditGateDecision{
		HasBaseline: hasBaseline,
		Tampered:    len(report.Tampered),
		Added:       len(report.Added),
		Missing:     len(report.Missing),
		Consistent:  report.Consistent,
	}
	if !hasBaseline {
		d.Kind = ModAuditGateAllow
		d.Reason = "尚无 mods 完整性基线，跳过启动拦截（建议先建立基线）"
		return d
	}
	if len(report.Tampered) > 0 {
		d.FirstTainted = report.Tampered[0].Name
		d.ForceUsed = force
		if !force {
			d.Blocked = true
			d.Kind = ModAuditGateBlock
			d.Reason = fmt.Sprintf("检测到 %d 个被篡改的 mod，已拦截启动", len(report.Tampered))
			return d
		}
		d.Kind = ModAuditGateAllowWarn
		d.Reason = fmt.Sprintf("检测到 %d 个被篡改的 mod，用户已强制放行", len(report.Tampered))
		return d
	}
	if len(report.Added) > 0 || len(report.Missing) > 0 {
		d.Kind = ModAuditGateAllowWarn
		d.Reason = modAuditGateWarnReason(d.Added, d.Missing)
		return d
	}
	d.Kind = ModAuditGateAllow
	d.Reason = "mods 目录与基线一致，允许启动"
	return d
}
