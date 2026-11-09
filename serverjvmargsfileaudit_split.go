package main

import (
	"os"
	"path/filepath"
	"strings"
)

func AuditServerJvmArgsFile(serverDir string) *JvmArgsAudit {
	a := &JvmArgsAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("user_jvm_args.txt", sjaReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "user_jvm_args.txt"
	path := filepath.Join(serverDir, rel)
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, sjaReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, sjaReasonLink, "JVM 参数文件是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, sjaReasonMiss, "未找到 user_jvm_args.txt", false)
		return a
	}
	data, err := readBoundedFile(path, sjaMaxFile)
	if err != nil {
		reason := sjaReasonRead
		if err == errLocalFileTooLarge {
			reason = sjaReasonLarge
		}
		a.add(rel, reason, err.Error(), true)
		return a
	}
	text := string(data)
	tokens := strings.Fields(strings.ReplaceAll(text, "\r\n", "\n"))
	quoteOpen := false
	for _, token := range tokens {
		if strings.HasPrefix(token, "#") {
			continue
		}
		if strings.Count(token, "\"")%2 == 1 {
			quoteOpen = !quoteOpen
		}
		lower := strings.ToLower(token)
		switch {
		case strings.HasPrefix(lower, "-javaagent:"):
			a.add(rel, sjaReasonAgent, token, true)
		case strings.HasPrefix(lower, "-agentlib:"):
			a.add(rel, sjaReasonAgent, token, true)
		case strings.HasPrefix(lower, "-agentpath:"):
			a.add(rel, sjaReasonAgent, token, true)
		case strings.HasPrefix(lower, "-xbootclasspath"):
			a.add(rel, sjaReasonBoot, token, true)
		case strings.HasPrefix(lower, "-xx:onerror"), strings.HasPrefix(lower, "-xx:onoutofmemoryerror"):
			a.add(rel, sjaReasonExec, token, true)
		case strings.HasPrefix(lower, "@"):
			a.add(rel, sjaReasonArg, token, true)
		case strings.Contains(lower, "java.security.manager=allow"):
			a.add(rel, sjaReasonPolicy, token, false)
		case strings.Contains(lower, "com.sun.management.jmxremote"):
			if !strings.Contains(lower, "authenticate=true") && !strings.Contains(lower, "ssl=true") {
				a.add(rel, sjaReasonJMX, token, false)
			}
		case strings.HasPrefix(lower, "-xmx") || strings.HasPrefix(lower, "-xms"):
			if gb, ok := sjaHeapGB(token[4:]); ok && gb > sjaMaxHeapGB {
				a.add(rel, sjaReasonHeap, token, false)
			}
		}
		if cfgHasControlChars(token) {
			a.add(rel, sjaReasonCTRL, "参数含控制字符", true)
		}
	}
	if quoteOpen {
		a.add(rel, sjaReasonQuote, "引号未闭合", true)
	}
	return a
}
