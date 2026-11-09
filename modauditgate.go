package main

// modauditgate.go —— mods 完整性审计的启动闸门决策内核。
//
// 背景：
//   modsaudit.go 只负责“建基线、对账、上报”，不产生任何放行决策；本文件把对账
//   报告翻译成启动前的“放行 / 拦截”结论，作为 LaunchGame 拉起 JVM 前的一道闸门。
//
// 决策口径（安全敏感，明确分级）：
//   - 基线不存在：放行并提示（首次审计友好，与 AuditModsIntegrity 一致）；
//   - 篡改（同名文件体积或哈希与基线不一致）：最接近“被恶意改写”的强信号，
//     默认拦截启动；仅当用户显式开启 force 强制放行时放行，且必须记录 Critical
//     审计事件并保留拦截理由；
//   - 新增（基线没有的文件）：放行但提示——新增 mod 仍会被 enforceInstalledMods
//     BeforeLaunch 的静态扫描拦高危形态，不该把“用户正常装了新 mod”也拦死；
//   - 缺失（基线有但目录里没了）：放行但提示——可能是用户主动删除。
//
// 本文件只做纯决策与文案，不碰磁盘 / 网络 / App 状态，可独立单测。

import (
	"fmt"
	"strings"
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

func modAuditGateWarnReason(added, missing int) string {
	parts := []string{}
	if added > 0 {
		parts = append(parts, fmt.Sprintf("新增 %d", added))
	}
	if missing > 0 {
		parts = append(parts, fmt.Sprintf("缺失 %d", missing))
	}
	return "mods 目录与基线有差异（" + strings.Join(parts, "、") + "），已放行，请留意来源"
}

// modAuditGateEventText 生成写审计事件的中文摘要。
func modAuditGateEventText(d ModAuditGateDecision) string {
	base := "mods 完整性启动闸门"
	if !d.HasBaseline {
		return base + ": 无基线，放行"
	}
	switch d.Kind {
	case ModAuditGateBlock:
		return fmt.Sprintf("%s: 拦截（篡改 %d，首个: %s）", base, d.Tampered, d.FirstTainted)
	case ModAuditGateAllowWarn:
		if d.ForceUsed {
			return fmt.Sprintf("%s: 强制放行（篡改 %d，首个: %s）", base, d.Tampered, d.FirstTainted)
		}
		return fmt.Sprintf("%s: 放行但提示（新增 %d / 缺失 %d）", base, d.Added, d.Missing)
	default:
		return fmt.Sprintf("%s: 放行（一致 %d）", base, d.Consistent)
	}
}
