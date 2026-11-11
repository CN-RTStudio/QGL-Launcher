package main

import (
	"fmt"
	"strings"
)

func (audit PortExposureAudit) Codes() []string {
	return findingCodes(audit.Findings, func(f PortFinding) string { return f.Reason })
}

func (audit PortExposureAudit) Describe() string {
	if len(audit.Findings) == 0 {
		return "端口暴露校验通过"
	}
	parts := make([]string, 0, len(audit.Findings))
	for _, finding := range audit.Findings {
		parts = append(parts, fmt.Sprintf("%s=%s(%s:%s)", finding.Key, finding.Value, finding.Reason, finding.Detail))
	}
	return strings.Join(parts, "；")
}
