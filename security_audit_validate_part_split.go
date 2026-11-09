package main

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
