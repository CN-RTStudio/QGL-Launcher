package main

import "time"

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
