package main

const (
	spxMaxConfigBytes = 256 * 1024
	spxMaxPluginDirs  = 128
	spxMaxNotes       = 64
	spxReasonSymlink  = "symlink"
	spxReasonTooLarge = "too-large"
	spxReasonUnread   = "unreadable"
	spxReasonBadFile  = "bad-config-file"
	spxReasonTooMany  = "too-many-plugins"
)

type spxNote = auditFinding

type spxConfig struct {
	Rel  string
	Text string
	Flat map[string]string
}

type spxScanResult struct {
	Configs []spxConfig
	Notes   []spxNote
}

func (r *spxScanResult) addNote(file, reason, detail string, blocking bool) {
	if len(r.Notes) >= spxMaxNotes {
		return
	}
	r.Notes = append(r.Notes, spxNote{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (r *spxScanResult) Blocking() bool {
	for _, note := range r.Notes {
		if note.Blocking {
			return true
		}
	}
	return false
}
