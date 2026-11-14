package main

import (
	"fmt"
	"strings"
)

func (audit DatapackAudit) Describe() string {
	if len(audit.Findings) == 0 {
		return "数据包目录未发现风险项"
	}
	var parts []string
	for _, finding := range audit.Findings {
		parts = append(parts, fmt.Sprintf("%s: %s", finding.Name, finding.Detail))
	}
	return strings.Join(parts, "；")
}
