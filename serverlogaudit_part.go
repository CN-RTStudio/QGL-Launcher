package main

import (
	"fmt"
	"strings"
)

var logExploitMarkers = []string{
	"${jndi:",
	"ldap://",
	"ldaps://",
	"rmi://",
	"dns://",
	"${lower:",
	"${upper:",
	"${env:",
}

type LogFinding struct {
	Name     string
	Reason   string
	Detail   string
	Blocking bool
}
type ServerLogAudit struct {
	Dir      string
	Present  bool
	Entries  int
	Findings []LogFinding
}

func (a *ServerLogAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f LogFinding) bool { return f.Blocking })
}
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
func (a *ServerLogAudit) Describe() string {
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Name == "" {
			parts = append(parts, fmt.Sprintf("%s: %s", f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s(%s): %s", f.Name, f.Reason, f.Detail))
	}
	return strings.Join(parts, "；")
}
