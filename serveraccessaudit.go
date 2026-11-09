package main

const (
	accessReasonOK         = "ok"
	accessReasonSymlink    = "symlink"
	accessReasonNotRegular = "not-regular"
	accessReasonTooLarge   = "too-large"
	accessReasonMalformed  = "malformed"
	accessReasonTooMany    = "too-many"
	accessReasonBadEntry   = "bad-entry"
	accessReasonDuplicate  = "duplicate"
	accessMaxFileBytes     = 4 << 20
	accessMaxEntries       = 512
	accessMaxNameRunes     = 64
	accessMinOpsLevel      = 1
	accessMaxOpsLevel      = 4
)

var accessFileNames = []string{
	"ops.json",
	"whitelist.json",
	"banned-players.json",
	"banned-ips.json",
}

type AccessFinding struct {
	File     string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

type AccessFileAudit struct {
	Name     string
	Present  bool
	Symlink  bool
	Entries  int
	Findings []AccessFinding
}

type ServerAccessAudit struct {
	Dir      string
	Files    []AccessFileAudit
	Findings []AccessFinding
}

type accessRecord struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Level   int    `json:"level"`
	IP      string `json:"ip"`
	Expires string `json:"expires"`
}
