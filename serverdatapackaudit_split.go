package main

import (
	"fmt"
	"strings"
)

func (a DataPackAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现数据包"
	}
	parts := []string{}
	for _, f := range a.Findings {
		where := f.File
		if where == "" {
			where = "server"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", where, f.Reason))
		if len(parts) >= 6 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a DataPackAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f DataPackFinding) bool { return f.Blocking }, func(f DataPackFinding) bool { return !f.Blocking && f.Reason != dpReasonOK })
	return fmt.Sprintf("packs=%d findings=%d blocking=%d warnings=%d", len(a.Packs), len(a.Findings), blocking, warnings)
}

func (a *DataPackAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, dpMaxFindings, DataPackFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

type packMeta struct {
	Pack struct {
		PackFormat  int         `json:"pack_format"`
		Description interface{} `json:"description"`
	} `json:"pack"`
}

func packDescription(value interface{}) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case map[string]interface{}:
		if text, ok := v["text"].(string); ok {
			return text, true
		}
		return "", false
	case nil:
		return "", true
	case []interface{}:
		return "", false
	default:
		return "", false
	}
}
