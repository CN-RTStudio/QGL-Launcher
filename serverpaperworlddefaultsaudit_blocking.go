package main

import ()

func (a *PaperWorldAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PaperWorldFinding) bool { return f.Blocking })
}

func (a *PaperWorldAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
