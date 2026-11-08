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
