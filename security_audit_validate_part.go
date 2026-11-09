package main

import (
	"os"
	"time"
)

// flushSuppressedLocked 把上一条事件在聚合窗口内被压下的重复次数补一条
// "repeated" 汇总记录，保证磁盘日志里既能看到首次事件，也能看到它后来又
// 触发了多少次，而不会每次都写一行。
func (s *securityAudit) flushSuppressedLocked(now time.Time) {
	if s.last == nil || s.suppressed == 0 {
		return
	}
	summary := SecurityEvent{
		OccurredAt: now,
		EpochMS:    now.UnixMilli(),
		Category:   s.last.Category,
		Severity:   s.last.Severity,
		Action:     auditActionRepeated,
		Source:     s.last.Source,
		Detail:     sanitizeAuditDetail(s.last.Detail),
		Count:      int(s.suppressed),
	}
	_ = s.appendLineLocked(summary)
	s.suppressed = 0
}

// record 是审计器核心：校验、脱敏、去重聚合、入内存环、落盘。
// 任何非法输入 / IO 失败都不会 panic 或返回影响调用方的错误。
func (s *securityAudit) record(category, severity, action, source, detail string) {
	if !validAuditCategory(category) || !validAuditSeverity(severity) || !validAuditAction(action) {
		return
	}
	source = sanitizeAuditDetail(source)
	detail = sanitizeAuditDetail(detail)
	if source == "" {
		source = "unknown"
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	key := auditDedupKey(category, action, source, detail)
	if s.last != nil && s.lastKey == key && now.Sub(s.last.OccurredAt) < auditDedupWindow {
		s.last.Count++
		s.last.OccurredAt = now
		s.suppressed++
		return
	}

	// 新类别事件到来：先把上一条的重复汇总落盘。
	s.flushSuppressedLocked(now)

	e := SecurityEvent{
		OccurredAt: now,
		EpochMS:    now.UnixMilli(),
		Category:   category,
		Severity:   severity,
		Action:     action,
		Source:     source,
		Detail:     detail,
		Count:      1,
	}
	s.pushRing(e)
	_ = s.appendLineLocked(e)
	s.lastKey = key
	copied := e
	s.last = &copied
}

// snapshot 返回内存环中事件的副本（按时间倒序：最新在前）。
// category 非空时只返回该类别。limit<=0 或超过环容量按环容量处理。
func (s *securityAudit) snapshot(category string, limit int) []SecurityEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.ring) {
		limit = len(s.ring)
	}
	out := make([]SecurityEvent, 0, limit)
	for i := len(s.ring) - 1; i >= 0 && len(out) < limit; i-- {
		e := s.ring[i]
		if category != "" && e.Category != category {
			continue
		}
		out = append(out, e)
	}
	return out
}

// clear 清空内存环与磁盘日志（含归档）。供前端"清空安全事件"调用。
func (s *securityAudit) clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ring = s.ring[:0]
	s.last = nil
	s.lastKey = ""
	s.suppressed = 0
	if !s.initialized {
		return nil
	}
	for _, p := range []string{s.filePath, s.filePath + auditLogArchiveSuffix} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	s.fileSize = 0
	return nil
}

// ===== 包级便捷函数：拦截点只调这些，不必关心实例 =====

// recordSecurityEvent 记录一条安全事件。
// detail 在落盘前统一过 reportmin 的值级去敏（剥本机绝对路径 / 令牌 / 长十六
// 进制 / 换行折叠），防止安全事件文件把本机结构或凭据泄给排查者与未来遥测通道。
func recordSecurityEvent(category, severity, action, source, detail string) {
	detail = ScrubTelemetryValue(detail)
	defaultSecurityAudit.record(category, severity, action, source, detail)
}

// snapshotSecurityEvents 供主进程 / 测试读取最近事件。
func snapshotSecurityEvents(category string, limit int) []SecurityEvent {
	return defaultSecurityAudit.snapshot(category, limit)
}

// clearSecurityEvents 清空内存与磁盘上的全部安全事件。
func clearSecurityEvents() error { return defaultSecurityAudit.clear() }

// ===== 暴露给 Wails 前端的方法（App 绑定方法）=====

// GetSecurityEvents 返回最近的安全事件，最新在前。
//
//	limit    ：条数，非法或超出范围时回落到默认 100，硬上限 1000；
//	category ：可选类别过滤，传非白名单类别时直接返回错误而不是悄悄返回空。
func (a *App) GetSecurityEvents(limit int, category string) ([]SecurityEvent, error) {
	if category != "" && !validAuditCategory(category) {
		return nil, &auditError{msg: "未知的安全事件类别"}
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > auditRingCap {
		limit = auditRingCap
	}
	return snapshotSecurityEvents(category, limit), nil
}

// ClearSecurityEvents 清空安全事件（内存环 + JSONL + 归档）。
func (a *App) ClearSecurityEvents() error {
	return clearSecurityEvents()
}
