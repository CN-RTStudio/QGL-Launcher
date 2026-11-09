package main

import (
	"fmt"
	"strings"
)

const (
	settingsSeverityInfo     = "info"
	settingsSeverityWarn     = "warn"
	settingsSeverityCritical = "critical"
	settingsRconMinPassword  = 8
	settingsMaxPlayersLimit  = 2000
)

type SettingFinding struct {
	Key      string
	Value    string
	Severity string
	Message  string
}
type ServerSettingsAudit struct {
	Findings []SettingFinding
}

func (audit ServerSettingsAudit) Blocking() bool {
	for _, finding := range audit.Findings {
		if finding.Severity == settingsSeverityCritical {
			return true
		}
	}
	return false
}
func (audit ServerSettingsAudit) HasWarnings() bool {
	return len(audit.Findings) > 0
}
func (audit ServerSettingsAudit) Codes() []string {
	var codes []string
	for _, finding := range audit.Findings {
		codes = append(codes, finding.Key+"="+finding.Value)
	}
	return codes
}
func (audit ServerSettingsAudit) Describe() string {
	if len(audit.Findings) == 0 {
		return "服务器配置未发现风险项"
	}
	var parts []string
	for _, finding := range audit.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s=%s): %s", finding.Severity, finding.Key, finding.Value, finding.Message))
	}
	return strings.Join(parts, "；")
}
