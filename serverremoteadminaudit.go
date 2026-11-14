package main

import ()

const (
	remoteReasonOK            = "ok"
	remoteReasonMissing       = "missing"
	remoteReasonTooLarge      = "too-large"
	remoteReasonNotRegular    = "not-regular"
	remoteReasonSymlink       = "symlink"
	remoteReasonEmptyPassword = "empty-password"
	remoteReasonShortPassword = "short-password"
	remoteReasonWeakPassword  = "weak-password"
	remoteReasonBadPort       = "bad-port"
	remoteReasonPortConflict  = "port-conflict"
	remoteReasonQueryOpen     = "query-open"
	remoteReasonOfflineMode   = "offline-mode"
	remoteReasonEnforceOff    = "whitelist-not-enforced"
	remoteReasonBindAll       = "bind-all"
	remoteReasonProxyBypass   = "proxy-bypass"
	remoteReasonBroadcastOps  = "broadcast-rcon"
	remoteReasonDuplicateKey  = "duplicate-key"
	remoteReasonBadLimit      = "bad-players"

	remoteMaxBytes         = 1 << 20
	remoteMinPasswordRunes = 8
)

var remoteWeakPasswords = []string{
	"rcon", "password", "changeme", "change-me", "minecraft", "12345678",
	"123456789", "admin", "qwerty", "letmein", "secret", "test1234",
}

var remoteWildcardBindings = []string{"0.0.0.0", "::", "*", "[::]"}

var remoteKeys = []string{
	"enable-rcon", "rcon.password", "rcon.port", "broadcast-rcon-to-ops",
	"enable-query", "query.port", "online-mode", "white-list", "enforce-whitelist",
	"server-ip", "prevent-proxy-connections", "max-players",
}

type RemoteFinding struct {
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerRemoteAudit struct {
	Path     string
	Present  bool
	Values   map[string]string
	Findings []RemoteFinding
}

func (a *ServerRemoteAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f RemoteFinding) bool { return f.Blocking })
}

func (a *ServerRemoteAudit) HasWarnings() bool {
	return a != nil && len(a.Findings) > 0
}

func (a *ServerRemoteAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodes(a.Findings, func(f RemoteFinding) string { return f.Reason })
}
