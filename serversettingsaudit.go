package main

import (
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

func settingOrDefault(props *serverProperties, key, fallback string) string {
	if value, ok := props.Get(key); ok {
		return value
	}
	return fallback
}

func settingBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}
