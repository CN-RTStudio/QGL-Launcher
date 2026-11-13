package main

import (
	"os"
	"time"
)

func validAuditSeverity(v string) bool {
	return v == auditSeverityInfo || v == auditSeverityWarn || v == auditSeverityCritical
}

func validAuditAction(a string) bool {
	return a == auditActionBlocked || a == auditActionRejected ||
		a == auditActionStripped || a == auditActionRepeated || a == auditActionDetected
}

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
