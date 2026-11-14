package main

import ()

func (a *UserCacheAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f UserCacheFinding) bool { return f.Blocking })
}

func (a *UserCacheAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
