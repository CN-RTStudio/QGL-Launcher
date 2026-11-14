package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func wrapTruncatedLog(text string, truncated bool) string {
	if !truncated {
		return text
	}
	return fmt.Sprintf("（日志超过 %d 字节，仅显示末尾部分）\n%s", logViewMaxBytes, text)
}

func redactLogBody(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = sanitizeLogLine(line)
	}
	return strings.Join(lines, "\n")
}

func (a *App) GetFullLog() string {
	if a.launchLogPath != "" {
		if text, truncated, err := readLogTail(a.launchLogPath, logViewMaxBytes); err == nil && len(text) > 0 {
			return redactLogBody(wrapTruncatedLog(text, truncated))
		}
	}
	fallback := filepath.Join(a.GetMinecraftDir(), "qgl_install.log")
	if text, truncated, err := readLogTail(fallback, logViewMaxBytes); err == nil {
		return redactLogBody(wrapTruncatedLog(text, truncated))
	}
	return "暂无日志"
}

func (a *App) ViewFullLog() {
	path, ok := a.guardedLogPath()
	if !ok {
		return
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
			return
		}
		if err := secureWritePrivateFile(path, []byte(a.GetFullLog())); err != nil {
			return
		}
	} else {
		bad, err := isSymlinkOrSpecial(path)
		if err != nil || bad || !info.Mode().IsRegular() {
			return
		}
	}
	cmd := exec.Command("notepad.exe", path)
	if err := cmd.Start(); err != nil {
		return
	}
}

func (a *App) ExportLogTxt() string {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "导出日志",
		DefaultFilename: "QGL日志.txt",
		Filters: []runtime.FileFilter{
			{DisplayName: "文本文件 (*.txt)", Pattern: "*.txt"},
		},
	})
	if err != nil || path == "" {
		return ""
	}
	if err := secureWritePrivateFile(path, []byte(a.GetFullLog())); err != nil {
		return ""
	}
	return path
}
