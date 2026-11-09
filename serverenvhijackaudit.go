package main

const (
	envReasonOK         = "ok"
	envReasonMissing    = "missing"
	envReasonUnreadable = "unreadable"
	envReasonTooLarge   = "too-large"
	envReasonSymlink    = "symlink"
	envReasonPreload    = "env-preload"
	envReasonShellInit  = "env-shell-init"
	envReasonClasspath  = "env-classpath"
	envReasonJVMAgent   = "env-jvm-agent"
	envReasonJVMOptions = "env-jvm-options"
	envReasonPathHijack = "env-path-hijack"
	envReasonToolInject = "env-tool-inject"
	envReasonPythonHook = "env-python-hook"
	envMaxFileBytes     = 1 << 20
	envMaxFindings      = 96
	envMaxScripts       = 20
	envMaxInlineDetail  = 96
)

var envScriptCandidates = []string{
	"start.sh", "start.bat", "start.cmd",
	"run.sh", "run.bat", "run.cmd",
	"launch.sh", "launch.bat", "launch.cmd",
	"server.sh", "server.bat", "server.cmd",
	"env.sh", "env.bat",
}

var envDangerousNames = map[string]string{
	"LD_PRELOAD":            envReasonPreload,
	"DYLD_INSERT_LIBRARIES": envReasonPreload,
	"LD_LIBRARY_PATH":       envReasonPathHijack,
	"DYLD_LIBRARY_PATH":     envReasonPathHijack,
	"BASH_ENV":              envReasonShellInit,
	"ENV":                   envReasonShellInit,
	"CLASSPATH":             envReasonClasspath,
	"_JAVA_OPTIONS":         envReasonJVMOptions,
	"JAVA_TOOL_OPTIONS":     envReasonJVMOptions,
	"JDK_JAVA_OPTIONS":      envReasonJVMOptions,
	"MAVEN_OPTS":            envReasonToolInject,
	"GRADLE_OPTS":           envReasonToolInject,
	"ANT_OPTS":              envReasonToolInject,
	"NODE_OPTIONS":          envReasonToolInject,
	"PYTHONPATH":            envReasonPythonHook,
	"PYTHONSTARTUP":         envReasonPythonHook,
}
