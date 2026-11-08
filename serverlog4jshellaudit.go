package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	ljMaxFindings      = 48
	ljMaxConfig        = 512 * 1024
	ljMaxJarName       = 128
	ljVulnVersion      = "2.17.0"
	ljReasonOK         = "ok"
	ljReasonMissing    = "missing"
	ljReasonVulnerable = "vulnerable-log4j"
	ljReasonJndiLookup = "jndi-lookup"
	ljReasonPattern    = "forced-lookup-pattern"
	ljReasonBadConfig  = "bad-config"
	ljReasonSymlink    = "symlink"
	ljReasonTooLarge   = "too-large"
	ljReasonBadName    = "bad-jar-name"
)

type Log4jFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type Log4jShellAudit struct {
	ServerDir string
	Jars      int
	Configs   int
	Findings  []Log4jFinding
}

func (a *Log4jShellAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= ljMaxFindings {
		return
	}
	a.Findings = append(a.Findings, Log4jFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *Log4jShellAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f Log4jFinding) bool { return f.Blocking })
}

func (a *Log4jShellAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if f.Reason != ljReasonOK && !f.Blocking {
			return true
		}
	}
	return false
}

func (a *Log4jShellAudit) Describe() string {
	return describeFindings(a.Findings, func(f Log4jFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func ljStripJarName(name string) (string, string) {
	base := strings.ToLower(filepath.Base(name))
	if !strings.HasSuffix(base, ".jar") {
		return "", ""
	}
	base = strings.TrimSuffix(base, ".jar")
	if !strings.HasPrefix(base, "log4j-core-") {
		return "", ""
	}
	version := strings.TrimPrefix(base, "log4j-core-")
	if version == "" {
		return "", ""
	}
	return base, version
}

func ljParseVersion(raw string) (int, int, int, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return 0, 0, 0, false
	}
	nums := make([]int, 0, 3)
	for i := 0; i < 3 && i < len(parts); i++ {
		chunk := parts[i]
		if i == 2 {
			idx := strings.IndexAny(chunk, "-+")
			if idx >= 0 {
				chunk = chunk[:idx]
			}
			if chunk == "" {
				chunk = "0"
			}
		}
		n, err := strconv.Atoi(chunk)
		if err != nil || n < 0 {
			return 0, 0, 0, false
		}
		nums = append(nums, n)
	}
	for len(nums) < 3 {
		nums = append(nums, 0)
	}
	return nums[0], nums[1], nums[2], true
}

func ljVersionVulnerable(major, minor int) bool {
	if major != 2 {
		return major == 1
	}
	return minor < 17
}

func ljScanJarDir(root, rel string, a *Log4jShellAudit) {
	dir := filepath.Join(root, rel)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return
	}
	_ = filepath.Walk(dir, func(path string, fi os.FileInfo, werr error) error {
		if werr != nil {
			return nil
		}
		if fi.IsDir() {
			return nil
		}
		relPath, rerr := filepath.Rel(root, path)
		if rerr != nil {
			relPath = path
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			a.add(relPath, ljReasonSymlink, "日志组件路径为符号链接", true)
			return nil
		}
		if len(filepath.Base(path)) > ljMaxJarName {
			a.add(relPath, ljReasonBadName, "文件名超长", false)
			return nil
		}
		base, version := ljStripJarName(path)
		if base == "" {
			return nil
		}
		a.Jars++
		major, minor, patch, ok := ljParseVersion(version)
		if !ok {
			a.add(relPath, ljReasonBadName, "版本号无法解析: "+version, false)
			return nil
		}
		if ljVersionVulnerable(major, minor) {
			a.add(relPath, ljReasonVulnerable, fmt.Sprintf("log4j-core %d.%d.%d 低于 %s", major, minor, patch, ljVulnVersion), true)
		}
		return nil
	})
}

func ljScanConfig(root string, a *Log4jShellAudit) {
	for _, rel := range []string{"log4j2.xml", "config/log4j2.xml"} {
		path := filepath.Join(root, rel)
		sym, serr := isSymlinkOrSpecial(path)
		if serr == nil && sym {
			a.add(rel, ljReasonSymlink, "配置文件为符号链接或特殊文件", true)
			continue
		}
		data, err := readBoundedFile(path, ljMaxConfig)
		if err != nil {
			if _, serr := os.Lstat(path); serr == nil {
				if strings.Contains(err.Error(), "too large") {
					a.add(rel, ljReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", ljMaxConfig), true)
				}
			}
			continue
		}
		a.Configs++
		text := strings.ToLower(string(data))
		if !strings.Contains(text, "log4j") && !strings.Contains(text, "appenders") {
			a.add(rel, ljReasonBadConfig, "内容不像 log4j2 配置", false)
			continue
		}
		if strings.Contains(text, "${jndi:") || strings.Contains(text, "%{jndi:") {
			a.add(rel, ljReasonJndiLookup, "配置中出现 JNDI 查找表达式", true)
		}
		if strings.Contains(text, "${ctx:") || strings.Contains(text, "$${") {
			a.add(rel, ljReasonPattern, "配置中出现强制查找占位符", false)
		}
		if strings.Contains(text, "<lookup") || strings.Contains(text, "lookups=") {
			a.add(rel, ljReasonPattern, "配置显式声明 lookup 扩展", true)
		}
	}
}

func AuditServerLog4jShell(serverDir string) *Log4jShellAudit {
	a := &Log4jShellAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", ljReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", ljReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", ljReasonMissing, "服务器目录不存在", false)
		return a
	}
	ljScanJarDir(serverDir, "libraries", a)
	ljScanJarDir(serverDir, "plugins", a)
	ljScanConfig(serverDir, a)
	if a.Jars == 0 && a.Configs == 0 {
		a.add(".", ljReasonMissing, "未发现 log4j 组件与配置", false)
	}
	return a
}
