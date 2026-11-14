package main

import ()

func (a *ServerLogAudit) HasWarnings() bool {
	if a == nil {
		return false
	}
	for _, f := range a.Findings {
		if !f.Blocking {
			return true
		}
	}
	return false
}
func (a *ServerLogAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodes(a.Findings, func(f LogFinding) string { return f.Reason })
}
