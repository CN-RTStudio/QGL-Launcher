package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
)

// scanLog4ShellNested 在有界预算内递归扫描嵌套 jar。
func scanLog4ShellNested(rep *Log4ShellReport, f *zip.File, display string, depth int,
	nestedCount *int, nestedBytes *int) {
	if depth >= log4jNestedDepth {
		rep.limitNested = true
		return
	}
	if *nestedCount >= log4jMaxNested || *nestedBytes >= log4jNestedBytesCap {
		rep.limitNested = true
		return
	}
	rc, err := f.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	left := log4jNestedBytesCap - *nestedBytes
	limit := int64(log4jPerNestedCap)
	if int64(left) < limit {
		limit = int64(left)
	}
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil || len(data) == 0 {
		return
	}
	childZr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		// 非合法 zip（损坏 / 伪装）不致命：jarscan 已有 nested-unreadable 告警。
		return
	}
	*nestedCount++
	*nestedBytes += len(data)
	scanLog4ShellInto(rep, childZr, depth+1, display+"!/", nestedCount, nestedBytes)
}

// enforceLog4ShellScan 是 Mod 安装链上的 Log4Shell 专用入口：扫描磁盘 jar，
// 把每条发现写入安全审计日志，出现 critical 返回错误（调用方负责删除临时
// 文件 / 终止导入）。
func enforceLog4ShellScan(jarPath, source, label string) (*Log4ShellReport, error) {
	rep, err := scanLog4ShellJar(jarPath)
	if err != nil {
		recordSecurityEvent(auditCategoryLog4Shell, auditSeverityCritical, auditActionBlocked,
			source, "log4j 扫描无法解析 jar，拒绝安装: "+sanitizeLogLine(label))
		return nil, err
	}

	critical := 0
	for _, f := range rep.Findings {
		action := auditActionDetected
		if f.Severity == JarSeverityCritical {
			action = auditActionBlocked
			critical++
		}
		detail := fmt.Sprintf("[%s] %s %s", f.Rule, f.Entry, f.Detail)
		recordSecurityEvent(auditCategoryLog4Shell, string(f.Severity), action, source,
			sanitizeLogLine(detail))
	}

	if critical > 0 {
		return rep, fmt.Errorf("Mod jar 命中 %d 个 Log4Shell/JNDI 高危项，已阻止安装: %s",
			critical, sanitizeLogLine(label))
	}
	return rep, nil
}
