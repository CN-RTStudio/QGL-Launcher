package main

import ()

func (a ServerPluginAudit) HasWarnings() bool {
	for _, finding := range a.Findings {
		if !finding.Blocking {
			return true
		}
	}
	return false
}
