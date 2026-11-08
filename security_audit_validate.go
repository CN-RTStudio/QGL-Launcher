package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

func sanitizeAuditDetail(detail string) string {
	s := sanitizeLogLine(detail)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	s = strings.TrimSpace(b.String())
	runes := []rune(s)
	if len(runes) > auditMaxDetailRunes {
		s = string(runes[:auditMaxDetailRunes]) + "…"
	}
	return s
}

func validAuditCategory(c string) bool {
	switch c {
	case auditCategoryZip, auditCategoryExternalURL, auditCategoryJVMEnv,
		auditCategoryInstaller, auditCategoryPrivateWrite, auditCategoryHashVerify,
		auditCategoryRateLimit, auditCategoryPermission, auditCategoryJarScan,
		auditCategoryLog4Shell, auditCategoryConsole, auditCategoryConfig,
		auditCategoryReclaim:
		return true
	}
	return false
}

func validAuditSeverity(v string) bool {
	return v == auditSeverityInfo || v == auditSeverityWarn || v == auditSeverityCritical
}

func validAuditAction(a string) bool {
	return a == auditActionBlocked || a == auditActionRejected ||
		a == auditActionStripped || a == auditActionRepeated || a == auditActionDetected
}

func auditDedupKey(category, action, source, detail string) string {
	// detail 只取前 96 个字符参与去重：路径前缀 / 主机名相同就算同一类事件，
	// 末尾变化的字节数 / 条目名不影响聚合判定。
	key := category + "\x00" + action + "\x00" + source + "\x00"
	runes := []rune(detail)
	if len(runes) > 96 {
		key += string(runes[:96])
	} else {
		key += detail
	}
	return key
}

// pushRing 以"新事件在末尾、超容从头丢弃"的方式维护定长环形缓冲。
func (s *securityAudit) pushRing(e SecurityEvent) {
	if len(s.ring) >= auditRingCap {
		copy(s.ring, s.ring[1:])
		s.ring[len(s.ring)-1] = e
		return
	}
	s.ring = append(s.ring, e)
}

// appendLineLocked 把一条事件以 JSONL 形式追加到文件，并在超限时轮转。
// 调用方必须持有 s.mu。任何 IO 错误都直接返回，由上层吞掉（审计不阻塞主流程）。
func (s *securityAudit) appendLineLocked(e SecurityEvent) error {
	if !s.initialized {
		return nil
	}
	if s.fileSize >= auditMaxFileBytes {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	// 每次追加前再做一次非普通文件检查：init 之后若有人把审计路径换成符号链接，
	// 这里在 O_APPEND（会跟随链接）之前拦下，防止写穿到链接目标。
	if err := rejectNonRegular(s.filePath); err != nil {
		return err
	}
	f, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, privateFilePerm)
	if err != nil {
		return err
	}
	n, err := f.Write(line)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	s.fileSize += int64(n)
	return nil
}

// rotateLocked 把当前日志改名归档，新事件从空文件重新开始写。
// 只保留一份 .1 归档：再次轮转时旧 .1 直接删除，避免无限堆积。
func (s *securityAudit) rotateLocked() error {
	archive := s.filePath + auditLogArchiveSuffix
	if _, err := os.Lstat(s.filePath); err != nil {
		if os.IsNotExist(err) {
			s.fileSize = 0
			return nil
		}
		return err
	}
	// 归档目标若已存在（含被人预埋的符号链接），先删链接本身再改名。
	if _, err := os.Lstat(archive); err == nil {
		if rmErr := os.Remove(archive); rmErr != nil {
			return rmErr
		}
	}
	if err := os.Rename(s.filePath, archive); err != nil {
		return err
	}
	s.fileSize = 0
	return nil
}

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
