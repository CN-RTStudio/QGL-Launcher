package main

const (
	packReasonOK           = "ok"
	packReasonMissing      = "missing"
	packReasonSymlink      = "symlink"
	packReasonUnreadable   = "unreadable"
	packReasonTooLarge     = "too-large"
	packReasonBadScheme    = "bad-scheme"
	packReasonInsecure     = "insecure-transport"
	packReasonUserinfo     = "url-userinfo"
	packReasonTooLong      = "url-too-long"
	packReasonBadHash      = "bad-hash"
	packReasonMissingHash  = "missing-hash"
	packReasonPlaceholder  = "placeholder-hash"
	packReasonBadPrompt    = "bad-prompt"
	packReasonDuplicateKey = "duplicate-key"
	packMaxURLLength       = 2048
	packMaxPromptRunes     = 256
	packSHA1HexLength      = 40
)

type PackFinding struct {
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerResourcePackAudit struct {
	Path     string
	Present  bool
	PackURL  string
	Findings []PackFinding
}

func (a *ServerResourcePackAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f PackFinding) bool { return f.Blocking })
}
