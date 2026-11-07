package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	sjaMaxFindings  = 28
	sjaMaxFile      = 64 * 1024
	sjaMaxHeapGB    = 32
	sjaReasonMiss   = "missing"
	sjaReasonLink   = "symlink"
	sjaReasonLarge  = "too-large"
	sjaReasonRead   = "unreadable"
	sjaReasonAgent  = "java-agent"
	sjaReasonBoot   = "bootclasspath"
	sjaReasonExec   = "on-error-command"
	sjaReasonArg    = "argfile-indirection"
	sjaReasonHeap   = "heap-too-large"
	sjaReasonPolicy = "security-manager"
	sjaReasonQuote  = "unbalanced-quote"
	sjaReasonCTRL   = "control-characters"
	sjaReasonJMX    = "jmx-exposed"
)

type JvmArgsFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type JvmArgsAudit struct {
	ServerDir string
	Findings  []JvmArgsFinding
}

func (a *JvmArgsAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= sjaMaxFindings {
		return
	}
	a.Findings = append(a.Findings, JvmArgsFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *JvmArgsAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *JvmArgsAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *JvmArgsAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "user_jvm_args.txt 未发现风险"
	}
	sorted := make([]JvmArgsFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Detail < sorted[j].Detail
	})
	var b strings.Builder
	for i, f := range sorted {
		if i >= 12 {
			b.WriteString(fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		if i > 0 {
			b.WriteString("；")
		}
		b.WriteString(f.Reason)
		if f.Detail != "" {
			b.WriteString("(")
			b.WriteString(f.Detail)
			b.WriteString(")")
		}
	}
	return b.String()
}

func sjaHeapGB(value string) (float64, bool) {
	upper := strings.ToUpper(strings.TrimSpace(value))
	mul := float64(1)
	switch {
	case strings.HasSuffix(upper, "G"):
		mul = 1
	case strings.HasSuffix(upper, "M"):
		mul = 1.0 / 1024.0
	case strings.HasSuffix(upper, "K"):
		mul = 1.0 / (1024.0 * 1024.0)
	default:
		return 0, false
	}
	number := strings.TrimSpace(upper[:len(upper)-1])
	v, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0, false
	}
	return v * mul, true
}

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
