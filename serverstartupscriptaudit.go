package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

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

func classifyStartupLine(line string) (string, string, bool, bool) {
	lower := strings.ToLower(line)
	trimmed := strings.TrimSpace(lower)

	if (hasAnyToken(trimmed, "curl ", "curl\t", "wget ", "wget\t", "invoke-webrequest", "iwr ") || trimmed == "curl" || trimmed == "wget") &&
		strings.Contains(trimmed, "|") && isShellToken(trimmed) {
		return startupReasonRemotePipe, "从网络拉取内容并直接交给 shell 执行", true, false
	}

	if hasAnyToken(trimmed, "powershell", "pwsh") &&
		hasAnyToken(trimmed, "-enc ", "-enc\t", "-encodedcommand") {
		return startupReasonEncodedPower, "PowerShell 编码命令可隐藏实际载荷", true, false
	}

	if hasAnyToken(trimmed, "/dev/tcp/", "nc -e", "ncat -e", "bash -i", "sh -i") {
		return startupReasonReverseShell, "反向 shell 特征", true, false
	}

	if hasAnyToken(trimmed, "base64") && hasAnyToken(trimmed, "-d ", "-d\t", "--decode") &&
		strings.Contains(trimmed, "|") && isShellToken(trimmed) {
		return startupReasonBase64Pipe, "base64 解码后管道交给 shell", true, false
	}

	if hasAnyToken(trimmed, "-javaagent", "-agentlib", "-agentpath") {
		return startupReasonJavaAgent, "脚本里注入 Java agent", true, false
	}

	if (hasAnyToken(trimmed, "certutil") && strings.Contains(trimmed, "-urlcache")) ||
		(hasAnyToken(trimmed, "bitsadmin") && strings.Contains(trimmed, "/transfer")) {
		return startupReasonDownloadCradle, "系统工具被用作下载器", false, false
	}

	if strings.Contains(trimmed, "eval $(") || strings.Contains(trimmed, "eval `") {
		return startupReasonEvalShell, "动态拼接命令并求值", true, false
	}

	if strings.Contains(trimmed, "rm -rf /") || strings.Contains(trimmed, "rm -rf ~") ||
		strings.Contains(trimmed, "del /f /s /q c:\\") || strings.Contains(trimmed, "del /s /q %systemdrive%") {
		return startupReasonBroadDelete, "大范围递归删除", false, false
	}

	if strings.Contains(trimmed, "chmod 777") || strings.Contains(trimmed, "chmod -r 777") ||
		strings.Contains(trimmed, "chmod 0777") {
		return startupReasonWorldChmod, "将文件放开为所有人可写", false, false
	}

	if strings.HasPrefix(trimmed, "sudo ") || strings.Contains(trimmed, " sudo ") {
		return startupReasonSudo, "脚本以提权方式运行", false, false
	}

	if hasAnyToken(trimmed, "password=", "passwd=", "token=", "secret=", "api_key=", "apikey=", "webhook=") {
		return startupReasonEmbeddedSecret, "脚本内直接写死凭据", false, false
	}

	return startupReasonOK, "", false, true
}

func truncateStartupLine(line string) string {
	line = strings.TrimSpace(line)
	if len(line) <= startupTruncatedDetailRunes {
		return line
	}
	return line[:startupTruncatedDetailRunes] + "..."
}

func readStartupScript(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, startupMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > startupMaxBytes {
		return nil, fmt.Errorf("脚本超过 %d 字节", startupMaxBytes)
	}
	return data, nil
}
