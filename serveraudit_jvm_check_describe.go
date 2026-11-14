package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *CrashReportHygieneAudit) Describe() string {
	return describeReasonDetail("crash-reports 未发现风险", a.Findings, 12)
}

var scgSecretMarkers = []string{"session-token", "accessToken", "rcon.password=", "Authorization: Bearer"}

func AuditServerCrashReports(serverDir string) *CrashReportHygieneAudit {
	a := &CrashReportHygieneAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("crash-reports", scgReasonMiss, "未配置服务器目录", false)
		return a
	}
	dir := filepath.Join(serverDir, "crash-reports")
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			a.add("crash-reports", scgReasonMiss, "未找到崩溃报告目录", false)
			return a
		}
		a.add("crash-reports", scgReasonRead, err.Error(), true)
		return a
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add("crash-reports", scgReasonLink, "崩溃报告目录是符号链接", true)
		return a
	}
	if !info.IsDir() {
		a.add("crash-reports", scgReasonRead, "崩溃报告路径不是目录", true)
		return a
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add("crash-reports", scgReasonRead, err.Error(), true)
		return a
	}
	var total int64
	reports := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		reports++
		if reports > scgMaxReports {
			a.add("crash-reports", scgReasonMany, fmt.Sprintf("报告数量超过 %d", scgMaxReports), false)
			break
		}
		name := entry.Name()
		if strings.ContainsAny(name, "<>|\x00") || strings.HasPrefix(name, ".") {
			a.add(name, scgReasonName, "文件名异常", false)
		}
		full := filepath.Join(dir, name)
		link, err := isSymlinkOrSpecial(full)
		if err != nil {
			a.add(name, scgReasonRead, err.Error(), true)
			continue
		}
		if link {
			a.add(name, scgReasonLink, "报告是符号链接或特殊文件", true)
			continue
		}
		stat, err := os.Stat(full)
		if err != nil {
			a.add(name, scgReasonRead, err.Error(), true)
			continue
		}
		total += stat.Size()
		if stat.Size() > scgMaxReport {
			a.add(name, scgReasonBig, fmt.Sprintf("%d 字节", stat.Size()), false)
			continue
		}
		data, err := readBoundedFile(full, scgMaxReport)
		if err != nil {
			a.add(name, scgReasonRead, err.Error(), true)
			continue
		}
		text := string(data)
		if strings.Contains(text, "level-seed=") || strings.Contains(text, "WorldSeed") {
			a.add(name, scgReasonSeed, "报告包含世界种子", false)
		}
		for _, marker := range scgSecretMarkers {
			if strings.Contains(text, marker) {
				a.add(name, scgReasonToken, "报告包含敏感标记 "+marker, true)
				break
			}
		}
	}
	if total > scgMaxTotalSize {
		a.add("crash-reports", scgReasonTotal, fmt.Sprintf("目录合计 %d 字节", total), false)
	}
	return a
}
