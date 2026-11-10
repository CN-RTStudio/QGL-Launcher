package main

import (
	"fmt"
	"sort"
	"strings"
)

func describeAuditFindings[T any](empty string, items []T, limit int, keys func(T) []string, line func(T) string) string {
	if len(items) == 0 {
		return empty
	}
	sorted := make([]T, len(items))
	copy(sorted, items)
	sort.SliceStable(sorted, func(i, j int) bool {
		left := keys(sorted[i])
		right := keys(sorted[j])
		for index := 0; index < len(left) && index < len(right); index++ {
			if left[index] != right[index] {
				return left[index] < right[index]
			}
		}
		return false
	})
	parts := make([]string, 0, limit+1)
	for index, item := range sorted {
		if index >= limit {
			parts = append(parts, fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		parts = append(parts, line(item))
	}
	return strings.Join(parts, "；")
}

func describeLabeledFindings[T any](empty string, items []T, limit int, labelDefault string, label func(T) string, reason func(T) string) string {
	if len(items) == 0 {
		return empty
	}
	parts := []string{}
	for _, item := range items {
		name := label(item)
		if name == "" {
			name = labelDefault
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", name, reason(item)))
		if len(parts) >= limit {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(items)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func describeTaggedFindings[T any](empty string, items []T, skip, labelDefault string, limit int, reason func(T) string, label func(T) string, detail func(T) string) string {
	parts := []string{}
	for _, item := range items {
		if reason(item) == skip {
			continue
		}
		name := label(item)
		if name == "" {
			name = labelDefault
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", name, reason(item), detail(item)))
		if len(parts) >= limit {
			break
		}
	}
	if len(parts) == 0 {
		return empty
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func describeFileReasonDetail(empty string, items []auditFinding, limit int) string {
	return describeAuditFindings(empty, items, limit,
		func(f auditFinding) []string { return []string{f.File, f.Reason, f.Detail} },
		func(f auditFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

func describeReasonDetail(empty string, items []auditFinding, limit int) string {
	return describeAuditFindings(empty, items, limit,
		func(f auditFinding) []string { return []string{f.Reason, f.Detail} },
		func(f auditFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func describeFileReason(empty string, items []auditFinding, limit int) string {
	return describeAuditFindings(empty, items, limit,
		func(f auditFinding) []string { return []string{f.File, f.Reason} },
		func(f auditFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

func describeFileDetail(empty string, items []auditFinding, limit int) string {
	return describeAuditFindings(empty, items, limit,
		func(f auditFinding) []string { return []string{f.File, f.Detail} },
		func(f auditFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}
