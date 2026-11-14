package main

import ()

const (
	startupReasonOK             = "ok"
	startupReasonMissing        = "missing"
	startupReasonSymlink        = "symlink"
	startupReasonNotRegular     = "not-regular"
	startupReasonTooLarge       = "too-large"
	startupReasonUnreadable     = "unreadable"
	startupReasonRemotePipe     = "remote-pipe"
	startupReasonEncodedPower   = "encoded-powershell"
	startupReasonReverseShell   = "reverse-shell"
	startupReasonBase64Pipe     = "base64-pipe"
	startupReasonJavaAgent      = "javaagent"
	startupReasonDownloadCradle = "download-cradle"
	startupReasonEvalShell      = "eval-shell"
	startupReasonBroadDelete    = "broad-delete"
	startupReasonWorldChmod     = "world-writable-chmod"
	startupReasonSudo           = "sudo-escalation"
	startupReasonEmbeddedSecret = "embedded-secret"
	startupMaxBytes             = 1 << 20
	startupMaxLineBytes         = 4096
	startupMaxFindings          = 256
	startupTruncatedDetailRunes = 160
)

var startupScriptNames = []string{
	"start.sh",
	"start.bat",
	"start.cmd",
	"run.sh",
	"run.bat",
	"run.cmd",
	"launch.sh",
	"launch.bat",
	"server.sh",
	"server.bat",
}

type StartupFinding struct {
	Script   string
	Line     int
	Reason   string
	Detail   string
	Blocking bool
}

type ServerStartupAudit struct {
	Dir      string
	Scripts  []string
	Findings []StartupFinding
}

func isShellToken(lower string) bool {
	return hasAnyToken(lower, "| sh", "| bash", "|sh", "|bash", "sh -c", "bash -c", "powershell", "pwsh", "cmd /c", "cmd.exe")
}
