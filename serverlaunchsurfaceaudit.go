package main

const (
	surfaceReasonOK         = "ok"
	surfaceReasonSymlink    = "symlink"
	surfaceReasonNotRegular = "not-regular"
	surfaceReasonExecutable = "executable"
	surfaceReasonExtraJar   = "extra-jar"
	surfaceReasonBadName    = "bad-name"
	surfaceReasonTooMany    = "too-many"
	surfaceReasonUnreadable = "unreadable"

	surfaceMaxEntries   = 2048
	surfaceMaxNameRunes = 128
)

var surfaceExecutableExts = []string{
	".exe", ".scr", ".com", ".pif", ".msi", ".bat", ".cmd",
	".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".sh",
}

type SurfaceFinding struct {
	Name     string
	Reason   string
	Detail   string
	Blocking bool
}
type ServerSurfaceAudit struct {
	Dir      string
	Entries  int
	Findings []SurfaceFinding
}

func (a *ServerSurfaceAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f SurfaceFinding) bool { return f.Blocking })
}

func (a *ServerSurfaceAudit) HasWarnings() bool {
	return a != nil && len(a.Findings) > 0
}
