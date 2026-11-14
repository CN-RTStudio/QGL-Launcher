package main

import ()

func (a TLSAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f TLSFinding) bool { return f.Blocking })
}
