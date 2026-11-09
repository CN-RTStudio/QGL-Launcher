package main

import "strings"

func (a *LaunchAudit) add(code, severity, field, detail string) {
	a.Findings = append(a.Findings, LaunchFinding{
		Code: code, Severity: severity, Field: field, Detail: detail,
	})
	a.tallyOne(severity)
}

// tally 重新统计全部 findings 的级别计数。审计函数都是先 append 结论、最后统一
// 调用它，避免在多处分散维护计数而漏算 / 重算。
func (a *LaunchAudit) tally() {
	a.Critical, a.Warns = 0, 0
	for _, f := range a.Findings {
		a.tallyOne(f.Severity)
	}
}

func (a *LaunchAudit) tallyOne(severity string) {
	switch severity {
	case launchSeverityCritical:
		a.Critical++
	case launchSeverityWarn:
		a.Warns++
	}
}

// HasCritical 报告是否存在必须阻断启动的结论。
func (a *LaunchAudit) HasCritical() bool { return a.Critical > 0 }

// FirstCriticalCode 返回第一条 critical 的稳定代码，无则空串，便于上层给出明确报错。
func (a *LaunchAudit) FirstCriticalCode() string {
	for _, f := range a.Findings {
		if f.Severity == launchSeverityCritical {
			return f.Code
		}
	}
	return ""
}

// hasTraversalSegment 报告路径按分隔符切分后是否出现独立的 ".." 段。
func hasTraversalSegment(p string) bool {
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}
