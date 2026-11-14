package main

import (
	"os"
	"path/filepath"
	"strings"
)

func envValueHasAgent(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "-javaagent") || strings.Contains(lower, "-agentlib") || strings.Contains(lower, "-agentpath")
}

func envScanLine(audit *EnvHijackAudit, script, line string) {
	name, value, ok := envSplitAssignment(line)
	if !ok {
		return
	}
	upper := envNameUpper(name)
	reason, known := envDangerousNames[upper]
	if !known {
		if upper == "PATH" && envPathIsHijacked(value) {
			audit.add(script, "PATH", envReasonPathHijack, "PATH 包含当前目录或临时目录: "+value, true)
		}
		return
	}
	switch reason {
	case envReasonPreload:
		audit.add(script, upper, reason, "动态链接器预加载可注入任意代码: "+value, true)
	case envReasonShellInit:
		audit.add(script, upper, reason, "shell 启动文件被重定向，可注入任意命令", true)
	case envReasonClasspath:
		audit.add(script, upper, reason, "显式 CLASSPATH 可加载任意 jar", true)
	case envReasonJVMOptions, envReasonToolInject:
		if envValueHasAgent(value) {
			audit.add(script, upper, envReasonJVMAgent, "环境变量静默注入 java agent: "+value, true)
			return
		}
		audit.add(script, upper, reason, "环境变量会静默改变 JVM/工具链行为: "+value, false)
	case envReasonPathHijack:
		audit.add(script, upper, reason, "库搜索路径被改写，可加载任意本地库: "+value, false)
	case envReasonPythonHook:
		audit.add(script, upper, reason, "Python 启动钩子可执行任意模块: "+value, false)
	}
}

func envInspectScript(audit *EnvHijackAudit, serverDir, name string) {
	path := filepath.Join(serverDir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	audit.Scripts = append(audit.Scripts, name)
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(name, "", envReasonSymlink, "启动脚本是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(name, "", envReasonUnreadable, "启动脚本不是普通文件", true)
		return
	}
	if info.Size() > envMaxFileBytes {
		audit.add(name, "", envReasonTooLarge, "启动脚本超过大小上限", true)
		return
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		audit.add(name, "", envReasonUnreadable, "启动脚本不可读", true)
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		envScanLine(audit, name, line)
	}
}

func AuditServerEnvironmentHijack(serverDir string) EnvHijackAudit {
	audit := EnvHijackAudit{Dir: serverDir}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		audit.add("server", "", envReasonMissing, "服务器目录不存在", true)
		return audit
	}
	for i, name := range envScriptCandidates {
		if i >= envMaxScripts {
			break
		}
		envInspectScript(&audit, serverDir, name)
	}
	if len(audit.Findings) == 0 {
		audit.add("", "", envReasonOK, "启动脚本未设置可被劫持的环境变量", false)
	}
	return audit
}

type EnvFinding struct {
	Script   string
	Variable string
	Reason   string
	Detail   string
	Blocking bool
}
type EnvHijackAudit struct {
	Dir      string
	Scripts  []string
	Findings []EnvFinding
}
