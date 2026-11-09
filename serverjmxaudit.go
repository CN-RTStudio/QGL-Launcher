package main

import (
	"path/filepath"
)

const (
	jmxReasonOK               = "ok"
	jmxReasonMissing          = "missing"
	jmxReasonUnreadable       = "unreadable"
	jmxReasonTooLarge         = "too-large"
	jmxReasonSymlink          = "symlink"
	jmxReasonUnauthenticated  = "jmx-unauthenticated"
	jmxReasonNoSSL            = "jmx-no-ssl"
	jmxReasonBroadBind        = "jmx-broad-bind"
	jmxReasonInlineSecret     = "jmx-inline-secret"
	jmxReasonPasswordReadable = "jmx-password-world-readable"
	jmxReasonPasswordUnsafe   = "jmx-password-unsafe"
	jmxMaxFileBytes           = 1 << 20
	jmxMaxFindings            = 128
	jmxMaxScripts             = 32
)

var jmxScriptCandidates = []string{
	"start.sh", "start.bat", "start.cmd",
	"run.sh", "run.bat", "run.cmd",
	"launch.sh", "launch.bat", "launch.cmd",
	"server.sh", "server.bat", "server.cmd",
	"jvm.args", "user_jvm_args.txt",
}

var jmxConfigCandidates = []string{
	"management.properties",
	filepath.Join("conf", "management.properties"),
	filepath.Join("config", "management.properties"),
	filepath.Join("conf", "jmxremote.password"),
	filepath.Join("config", "jmxremote.password"),
	filepath.Join("conf", "jmxremote.access"),
}

type JMXFinding = auditFinding
