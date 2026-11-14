package main

import ()

func (a *PurpurAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PurpurFinding) bool { return f.Blocking })
}

func (a *PurpurAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
