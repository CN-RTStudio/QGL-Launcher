package main

const (
	strayReasonOK            = "ok"
	strayReasonSymlink       = "symlink"
	strayReasonNotRegular    = "not-regular"
	strayReasonTooLarge      = "too-large"
	strayReasonUnreadable    = "unreadable"
	strayReasonPrivateKey    = "private-key"
	strayReasonCloudSecret   = "cloud-credential"
	strayReasonEnvSecret     = "env-secret"
	strayReasonKeystore      = "keystore"
	strayReasonWorldReadable = "world-readable"
	strayMaxFileBytes        = 256 << 10
	strayMaxCandidates       = 200
	strayMaxDepth            = 2
	straySniffBytes          = 8 << 10
)

var straySecretDirs = []string{".", "config", "plugins", "plugins/config"}
var straySecretNames = map[string]bool{
	".env": true, ".env.local": true, ".env.production": true,
	"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true,
	".npmrc": true, ".pypirc": true, ".netrc": true,
	"credentials": true, "credentials.json": true,
	"keystore": true, "keystore.jks": true,
	"database.yml": true, "secrets.yml": true,
}

type StraySecretFinding struct {
	Path     string
	Reason   string
	Detail   string
	Blocking bool
}
type ServerStraySecretAudit struct {
	Dir      string
	Scanned  []string
	Findings []StraySecretFinding
}
