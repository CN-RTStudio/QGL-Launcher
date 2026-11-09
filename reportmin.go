package main

import (
	"strings"
)

// reportMin 资源上界（默认策略）。
const (
	reportMinMaxBytes      = 8 << 20 // 序列化总预算 8MB
	reportMinMaxArrayItems = 500     // 单数组最多保留条数
	reportMinMaxDepth      = 8       // 嵌套深度上限
	reportMinMaxFieldLen   = 400     // 单字段值最大字节数
)

// reportAllowedFields 是允许进入上报的字段名白名单（键统一小写，匹配时大小写不敏感）。
// 白名单之外的字段（如环境变量、绝对路径、内部 ID）一律丢弃。
var reportAllowedFields = map[string]bool{
	"version":       true,
	"generatedat":   true,
	"baselineat":    true,
	"baselinedirs":  true,
	"total":         true,
	"consistent":    true,
	"skipped":       true,
	"limithit":      true,
	"hasrisks":      true,
	"added":         true,
	"missing":       true,
	"tampered":      true,
	"addedcount":    true,
	"missingcount":  true,
	"tamperedcount": true,
	"eventid":       true,
	"category":      true,
	"severity":      true,
	"action":        true,
	"source":        true,
	"detail":        true,
	"host":          true,
	"count":         true,
	"kind":          true,
	"dir":           true,
	"relpath":       true,
	"name":          true,
	"ok":            true,
}

// ReportPolicy 是一次最小化的策略参数（可注入以便测试边界）。
type ReportPolicy struct {
	MaxBytes      int
	MaxArrayItems int
	MaxDepth      int
	MaxFieldLen   int
	AllowField    func(string) bool
}

// defaultReportPolicy 返回默认上报策略（全字段上界取常量）。
func defaultReportPolicy() ReportPolicy {
	return ReportPolicy{
		MaxBytes:      reportMinMaxBytes,
		MaxArrayItems: reportMinMaxArrayItems,
		MaxDepth:      reportMinMaxDepth,
		MaxFieldLen:   reportMinMaxFieldLen,
		AllowField: func(field string) bool {
			return reportAllowedFields[strings.ToLower(field)]
		},
	}
}
