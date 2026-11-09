package main

const (
	soaMaxFindings  = 32
	soaMaxFile      = 512 * 1024
	soaMaxOperators = 64
	soaMaxLevel     = 4
	soaBusyOps      = 8
	soaReasonMiss   = "missing"
	soaReasonLink   = "symlink"
	soaReasonLarge  = "too-large"
	soaReasonRead   = "unreadable"
	soaReasonShape  = "invalid-shape"
	soaReasonLargeN = "too-many-operators"
	soaReasonUUID   = "invalid-uuid"
	soaReasonName   = "invalid-name"
	soaReasonLevel  = "invalid-level"
	soaReasonBypass = "invalid-bypass-flag"
	soaReasonDup    = "duplicate-operator"
	soaReasonOwner  = "owner-level-operator"
	soaReasonBusy   = "many-privileged-operators"
	soaReasonEmpty  = "empty-operator-list"
)

type OpsJsonFinding = auditFinding
type OpsJsonAudit struct {
	ServerDir string
	Findings  []OpsJsonFinding
}
type opsJsonEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               *int   `json:"level"`
	BypassesPlayerLimit *bool  `json:"bypassesPlayerLimit"`
}
