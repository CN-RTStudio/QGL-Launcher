package main

const (
	proxyReasonOK                = "ok"
	proxyReasonMissing           = "missing"
	proxyReasonSymlink           = "symlink"
	proxyReasonTooLarge          = "too-large"
	proxyReasonUnreadable        = "unreadable"
	proxyReasonBadYAML           = "bad-yaml"
	proxyReasonDuplicateKey      = "duplicate-key"
	proxyReasonProxyExposed      = "proxy-exposed"
	proxyReasonOnlineModeOff     = "proxy-online-mode-off"
	proxyReasonLegacyBungee      = "legacy-bungee"
	proxyReasonEmptySecret       = "empty-forwarding-secret"
	proxyReasonWeakSecret        = "weak-forwarding-secret"
	proxyReasonPlaceholderSecret = "placeholder-forwarding-secret"
	proxyReasonSecretMissing     = "secret-file-missing"
	proxyReasonSecretPermissive  = "secret-file-permissive"
	proxyReasonSecretSymlink     = "secret-file-symlink"
	proxyMaxConfigBytes          = 1 << 20
	proxyMinSecretRunes          = 12
	proxyMaxSecretRunes          = 256
)

var proxyPlaceholderSecrets = map[string]bool{
	"": true, "secret": true, "changeme": true, "change-me": true,
	"your-secret-here": true, "yoursecret": true, "password": true,
	"velocity-secret": true, "forwarding-secret": true, "todo": true,
}

type ProxyFinding struct {
	File     string
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerProxyAudit struct {
	Files        []string
	ProxyEnabled bool
	Provider     string
	Findings     []ProxyFinding
}

func (a *ServerProxyAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ProxyFinding) bool { return f.Blocking })
}

func (a *ServerProxyAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f ProxyFinding) bool {
		return !f.Blocking && f.Reason != proxyReasonOK && f.Reason != proxyReasonMissing
	})
}
