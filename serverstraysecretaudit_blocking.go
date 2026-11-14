package main

import ()

func (a *ServerStraySecretAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f StraySecretFinding) bool { return f.Blocking })
}
