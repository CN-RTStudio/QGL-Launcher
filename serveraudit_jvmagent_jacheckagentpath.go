package main

import (
	"os"
	"path/filepath"
	"strings"
)

func jaCheckAgentPath(a *JVMAgentAudit, file, raw string) {
	path := strings.TrimSpace(strings.Trim(raw, `"`))
	if path == "" {
		a.add(file, jaReasonAgentMissing, "代理参数缺少路径", true)
		return
	}
	if strings.Contains(path, "..") {
		a.add(file, jaReasonAgentTraversal, "代理路径包含上级目录引用", true)
		return
	}
	resolved := path
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(a.Dir, resolved)
	}
	absDir, errDir := filepath.Abs(a.Dir)
	absFile, errFile := filepath.Abs(resolved)
	if errDir == nil && errFile == nil {
		rel, err := filepath.Rel(absDir, absFile)
		if err == nil && (rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			a.add(file, jaReasonAgentOutside, "代理 jar 位于服务器目录之外", true)
			return
		}
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		a.add(file, jaReasonAgentMissing, "代理 jar 不存在", false)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(file, jaReasonSymlink, "代理 jar 是符号链接", true)
	}
}

func jaInspectLine(a *JVMAgentAudit, file, line string) {
	for _, token := range jaSplitTokens(line) {
		if strings.HasPrefix(token, "#") {
			return
		}
		if path, ok := jaAgentPath(token); ok {
			jaCheckAgentPath(a, file, path)
			continue
		}
		lower := strings.ToLower(token)
		switch {
		case strings.HasPrefix(token, "-agentlib:"):
			value := strings.TrimPrefix(token, "-agentlib:")
			if strings.HasPrefix(strings.ToLower(value), "jdwp") {
				a.add(file, jaReasonDebugAgent, "开启 JDWP 调试代理", true)
				if strings.Contains(strings.ToLower(value), "address=*") ||
					strings.Contains(strings.ToLower(value), "address=0.0.0.0") {
					a.add(file, jaReasonDebugAgent, "调试代理监听全部接口", true)
				}
				continue
			}
			a.add(file, jaReasonAgentLib, "使用 agentlib 加载本地代理", false)
		case strings.HasPrefix(lower, "-xbootclasspath"):
			a.add(file, jaReasonBootClasspath, "覆盖引导类路径", true)
		case strings.HasPrefix(lower, "-djava.security.manager=allow"):
			a.add(file, jaReasonSecurityMgr, "允许运行时安装安全管理器", false)
		case strings.HasPrefix(lower, "-dcom.sun.management.jmxremote.authenticate=false"):
			a.add(file, jaReasonJMXOpen, "JMX 关闭认证", true)
		case strings.HasPrefix(lower, "-dcom.sun.management.jmxremote.port="):
			a.add(file, jaReasonJMXOpen, "开放 JMX 远程端口", false)
		}
	}
}

func jaInspectScript(a *JVMAgentAudit, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	rel, relErr := filepath.Rel(a.Dir, path)
	if relErr != nil {
		rel = filepath.Base(path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(rel, jaReasonSymlink, "启动脚本是符号链接", true)
		return
	}
	if info.Size() > jaMaxScriptBytes {
		a.add(rel, jaReasonTooLarge, "启动脚本超过体积预算", true)
		return
	}
	data, err := readBoundedFile(path, jaMaxScriptBytes)
	if err != nil {
		a.add(rel, jaReasonUnreadable, "启动脚本不可读", true)
		return
	}
	a.Scripts = append(a.Scripts, rel)
	for _, line := range strings.Split(string(data), "\n") {
		jaInspectLine(a, rel, strings.TrimSpace(line))
	}
}
