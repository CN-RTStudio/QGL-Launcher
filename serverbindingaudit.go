package main

import (
	"sort"
)

const (
	bindingReasonOK           = "ok"
	bindingReasonMissing      = "missing"
	bindingReasonSymlink      = "symlink"
	bindingReasonTooLarge     = "too-large"
	bindingReasonUnreadable   = "unreadable"
	bindingReasonBadBoolean   = "bad-boolean"
	bindingReasonOfflineMode  = "offline-mode"
	bindingReasonBindAll      = "bind-all-interfaces"
	bindingReasonBindPublic   = "bind-public-address"
	bindingReasonBindLoopback = "bind-loopback"
	bindingReasonBadBind      = "bad-bind-address"
	bindingReasonSecureChat   = "secure-profile-unenforced"
	bindingReasonProxyAllowed = "proxy-connections-allowed"
	bindingReasonStatusPublic = "status-exposed"
	bindingReasonBadCompress  = "bad-compression-threshold"
	bindingReasonBadPlayerCap = "bad-player-cap"
	bindingReasonBadViewDist  = "bad-view-distance"
)

type BindingFinding struct {
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerBindingAudit struct {
	Path     string
	Present  bool
	Findings []BindingFinding
}

func (a *ServerBindingAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f BindingFinding) bool { return f.Blocking })
}

func (a *ServerBindingAudit) HasWarnings() bool {
	if a == nil {
		return false
	}
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != bindingReasonOK {
			return true
		}
	}
	return false
}

func (a *ServerBindingAudit) Codes() []string {
	if a == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(a.Findings))
	codes := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == bindingReasonOK {
			continue
		}
		if _, ok := seen[f.Reason]; ok {
			continue
		}
		seen[f.Reason] = struct{}{}
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}
