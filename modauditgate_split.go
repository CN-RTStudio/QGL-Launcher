package main

import (
	"fmt"
	"strings"
)

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
