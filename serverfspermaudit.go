package main

const (
	fsPermReasonOK            = "ok"
	fsPermReasonMissing       = "missing"
	fsPermReasonSymlink       = "symlink"
	fsPermReasonNotRegular    = "not-regular"
	fsPermReasonUnreadable    = "unreadable"
	fsPermReasonWorldWritable = "world-writable"
	fsPermReasonGroupWritable = "group-writable"
	fsPermReasonWorldReadable = "secret-world-readable"
	fsPermReasonExecutable    = "executable-config"
	fsPermReasonSpecialBit    = "special-bit"
	fsPermReasonPlatform      = "unsupported-platform"
)

type FSPermFinding struct {
	Path     string
	Mode     string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerFSPermAudit struct {
	Dir      string
	Checked  []string
	Findings []FSPermFinding
}

func (a *ServerFSPermAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f FSPermFinding) bool { return f.Blocking })
}

func (a *ServerFSPermAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f FSPermFinding) bool {
		return !f.Blocking && f.Reason != fsPermReasonOK && f.Reason != fsPermReasonMissing && f.Reason != fsPermReasonPlatform
	})
}
