package main

import "os"

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
