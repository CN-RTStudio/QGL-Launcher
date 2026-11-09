package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
