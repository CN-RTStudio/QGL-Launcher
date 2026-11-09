package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

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

func auditStartupFile(audit *ServerStartupAudit, dir, name string) {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	audit.Scripts = append(audit.Scripts, name)
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, StartupFinding{Script: name, Reason: startupReasonSymlink, Detail: "脚本是符号链接，内容不可信", Blocking: true})
		return
	}
	if !info.Mode().IsRegular() {
		audit.Findings = append(audit.Findings, StartupFinding{Script: name, Reason: startupReasonNotRegular, Detail: "不是常规文件", Blocking: false})
		return
	}
	if info.Size() > startupMaxBytes {
		audit.Findings = append(audit.Findings, StartupFinding{Script: name, Reason: startupReasonTooLarge, Detail: fmt.Sprintf("%d 字节超过上限", info.Size()), Blocking: false})
		return
	}
	data, err := readStartupScript(path)
	if err != nil {
		reason := startupReasonUnreadable
		if strings.Contains(err.Error(), "超过") {
			reason = startupReasonTooLarge
		}
		audit.Findings = append(audit.Findings, StartupFinding{Script: name, Reason: reason, Detail: truncateStartupLine(err.Error()), Blocking: false})
		return
	}
	lines := bytes.Split(data, []byte("\n"))
	for idx, raw := range lines {
		line := string(raw)
		if len(raw) > startupMaxLineBytes {
			line = string(raw[:startupMaxLineBytes])
		}
		reason, detail, blocking, ok := classifyStartupLine(line)
		if ok {
			continue
		}
		if len(audit.Findings) >= startupMaxFindings {
			return
		}
		audit.Findings = append(audit.Findings, StartupFinding{
			Script:   name,
			Line:     idx + 1,
			Reason:   reason,
			Detail:   detail + ": " + truncateStartupLine(line),
			Blocking: blocking,
		})
	}
}

func AuditServerStartupScripts(serverDir string) *ServerStartupAudit {
	audit := &ServerStartupAudit{Dir: serverDir}
	if strings.TrimSpace(serverDir) == "" {
		audit.Findings = append(audit.Findings, StartupFinding{Script: "", Reason: startupReasonMissing, Detail: "未提供服务器目录"})
		return audit
	}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.Findings = append(audit.Findings, StartupFinding{Script: "", Reason: startupReasonMissing, Detail: "服务器目录不存在"})
		return audit
	}
	for _, name := range startupScriptNames {
		auditStartupFile(audit, serverDir, name)
	}
	if len(audit.Scripts) == 0 {
		audit.Findings = append(audit.Findings, StartupFinding{Script: "", Reason: startupReasonMissing, Detail: "未找到启动脚本"})
	}
	return audit
}
