package main

import (
	"fmt"
	"strings"
)

func describeServerJarAudit(audit ServerJarAudit) string {
	var parts []string
	parts = append(parts, audit.Describe())
	if audit.Size > 0 {
		parts = append(parts, fmt.Sprintf("大小 %d 字节", audit.Size))
	}
	if audit.SidecarPresent {
		parts = append(parts, "侧车已校验")
	}
	if audit.Entries > 0 {
		parts = append(parts, fmt.Sprintf("条目 %d 个", audit.Entries))
	}
	if len(audit.Warnings) > 0 {
		parts = append(parts, strings.Join(audit.Warnings, "；"))
	}
	return strings.Join(parts, "，")
}
