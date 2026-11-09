package main

const (
	skReasonOK            = "ok"
	skReasonSymlink       = "symlink"
	skReasonTooLarge      = "too-large"
	skReasonWorldWritable = "world-writable"
	skReasonWorldReadable = "world-readable"
	skReasonUnreadable    = "unreadable"
	skReasonPlainSecret   = "plaintext-secret"
	skReasonPropSecret    = "system-property-secret"
	skReasonURLCreds      = "url-credentials"
	skReasonTokenArg      = "token-argument"
	skReasonRCONArg       = "rcon-password-argument"
	skReasonEnvSecret     = "env-secret"
	skReasonMissing       = "missing"

	skMaxFileBytes = 256 << 10
	skMaxFiles     = 16
	skMaxFindings  = 48
)

var skScriptFiles = []string{
	"start.sh",
	"start.bat",
	"start.cmd",
	"run.sh",
	"run.bat",
	"run.cmd",
	"launch.sh",
	"launch.bat",
	"launch.cmd",
	"user_jvm_args.txt",
	"jvm.args",
	"server.args",
}

var skSecretKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"apikey",
	"api-key",
	"api_key",
	"accesskey",
	"access-key",
	"rcon.password",
	"rcon-password",
}
