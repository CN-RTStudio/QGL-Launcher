package main

import ()

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
