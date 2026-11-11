package main

import (
	"fmt"
)

func (a *ServerResourcePackAudit) auditDuplicateKeys(props *serverProperties) {
	counts := make(map[string]int, len(props.lines))
	for _, line := range props.lines {
		if !line.isPair {
			continue
		}
		counts[line.key]++
	}
	for key, count := range counts {
		if count < 2 {
			continue
		}
		a.Findings = append(a.Findings, PackFinding{
			Key: key, Reason: packReasonDuplicateKey,
			Detail: fmt.Sprintf("键出现 %d 次，最终生效值取决于解析顺序", count),
		})
	}
}
