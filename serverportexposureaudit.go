package main

const (
	pxReasonOK            = "ok"
	pxReasonMissing       = "missing"
	pxReasonUnreadable    = "unreadable"
	pxReasonSymlink       = "symlink"
	pxReasonBadPort       = "bad-port"
	pxReasonPortConflict  = "port-conflict"
	pxReasonBindAll       = "bind-all-interfaces"
	pxReasonLowPort       = "privileged-port"
	pxReasonRconOpen      = "rcon-without-password"
	pxReasonWeakPassword  = "weak-rcon-password"
	pxReasonStaleSecret   = "stale-rcon-password"
	pxReasonRconExposed   = "rcon-all-interfaces"
	pxReasonQueryOpen     = "query-without-limit"
	pxReasonProxyBypass   = "proxy-bypass-off"
	pxReasonTooLarge      = "too-large"
	pxReasonWorldWritable = "world-writable"

	pxMaxPropertiesBytes = 1 << 20
	pxMaxFindings        = 64
	pxMinPasswordLength  = 8
)

var pxWeakPasswords = []string{
	"rcon",
	"password",
	"changeme",
	"minecraft",
	"admin",
	"123456",
	"12345678",
	"letmein",
	"secret",
	"test",
}

var pxForbiddenPorts = map[int]string{
	25:    "smtp",
	135:   "msrpc",
	139:   "netbios",
	445:   "smb",
	1433:  "mssql",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgres",
	6379:  "redis",
	8080:  "http-proxy",
	27017: "mongodb",
}
