package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
