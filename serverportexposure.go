package main

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	portReasonOK           = "ok"
	portReasonSymlink      = "symlink"
	portReasonNotRegular   = "not-regular"
	portReasonTooLarge     = "too-large"
	portReasonMissingFile  = "missing-file"
	portReasonBadNumber    = "bad-port"
	portReasonOutOfRange   = "out-of-range"
	portReasonConflict     = "port-conflict"
	portReasonPrivileged   = "privileged-port"
	portReasonDisabledPort = "disabled-with-port"
	portMaxPropertiesBytes = int64(1) << 20
	defaultServerPort      = 25565
	defaultQueryPort       = 25565
	defaultRconPort        = 25575
	defaultManagementPort  = -1
)

type PortFinding struct {
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type PortExposureAudit struct {
	Path     string
	Present  bool
	Ports    map[string]int
	Findings []PortFinding
}

func (audit PortExposureAudit) Blocking() bool {
	return anyBlocking(audit.Findings, func(f PortFinding) bool { return f.Blocking })
}

func (audit PortExposureAudit) HasWarnings() bool {
	return len(audit.Findings) > 0 && !audit.Blocking()
}

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

func parsePortValue(key, raw string) (int, *PortFinding) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, &PortFinding{Key: key, Value: raw, Reason: portReasonBadNumber, Detail: "端口为空", Blocking: true}
	}
	if strings.HasPrefix(trimmed, "-") || strings.ContainsAny(trimmed, " \t") {
		return 0, &PortFinding{Key: key, Value: raw, Reason: portReasonBadNumber, Detail: "端口含非法字符", Blocking: true}
	}
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] < '0' || trimmed[i] > '9' {
			return 0, &PortFinding{Key: key, Value: raw, Reason: portReasonBadNumber, Detail: "端口含非数字字符", Blocking: true}
		}
	}
	if len(trimmed) > 1 && trimmed[0] == '0' {
		return 0, &PortFinding{Key: key, Value: raw, Reason: portReasonBadNumber, Detail: "端口含前导零歧义", Blocking: true}
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, &PortFinding{Key: key, Value: raw, Reason: portReasonBadNumber, Detail: "端口不是整数", Blocking: true}
	}
	if value < 1 || value > 65535 {
		return value, &PortFinding{Key: key, Value: raw, Reason: portReasonOutOfRange, Detail: "端口超出 1-65535", Blocking: true}
	}
	return value, nil
}
