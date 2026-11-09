package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	setbMaxFindings = 24
	setbMaxFile     = 512 * 1024
	setbMaxLine     = 512
	setbReasonMiss  = "missing"
	setbReasonLink  = "symlink"
	setbReasonLarge = "too-large"
	setbReasonRead  = "unreadable"
	setbReasonBOM   = "utf8-bom"
	setbReasonUTF8  = "invalid-utf8"
	setbReasonCRLF  = "crlf-endings"
	setbReasonNUL   = "nul-byte"
	setbReasonDup   = "duplicate-key"
	setbReasonKey   = "invalid-key"
	setbReasonLong  = "long-line"
	setbReasonEsc   = "bad-escape"
)

type PropertiesEncodingFinding = auditFinding

type PropertiesEncodingAudit struct {
	ServerDir string
	Findings  []PropertiesEncodingFinding
}

func (a *PropertiesEncodingAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= setbMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PropertiesEncodingFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PropertiesEncodingAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PropertiesEncodingFinding) bool { return f.Blocking })
}

func (a *PropertiesEncodingAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PropertiesEncodingAudit) Describe() string {
	return describeAuditFindings("server.properties 编码未发现风险", a.Findings, 12,
		func(f PropertiesEncodingFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f PropertiesEncodingFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func setbValidKey(key string) bool {
	if key == "" || len(key) > 64 {
		return false
	}
	for _, r := range key {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

func AuditServerPropertiesEncoding(serverDir string) *PropertiesEncodingAudit {
	a := &PropertiesEncodingAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("server.properties", setbReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "server.properties"
	path := filepath.Join(serverDir, rel)
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, setbReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, setbReasonLink, "属性文件是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, setbReasonMiss, "未找到 server.properties", false)
		return a
	}
	data, err := readBoundedFile(path, setbMaxFile)
	if err != nil {
		reason := setbReasonRead
		if err == errLocalFileTooLarge {
			reason = setbReasonLarge
		}
		a.add(rel, reason, err.Error(), true)
		return a
	}
	if len(data) > 0 && data[0] == 0xEF {
		if len(data) >= 3 && data[1] == 0xBB && data[2] == 0xBF {
			a.add(rel, setbReasonBOM, "文件带 UTF-8 BOM", true)
		}
	}
	if strings.Contains(string(data), "\x00") {
		a.add(rel, setbReasonNUL, "文件含 NUL 字节", true)
	}
	if !utf8.Valid(data) {
		a.add(rel, setbReasonUTF8, "文件不是合法 UTF-8", true)
	}
	text := string(data)
	if strings.Contains(text, "\r\n") {
		a.add(rel, setbReasonCRLF, "使用 CRLF 换行", false)
	}
	keys := map[string]int{}
	for idx, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if len(raw) > setbMaxLine {
			a.add(rel, setbReasonLong, "第 "+strconv.Itoa(idx+1)+" 行过长", false)
			continue
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		eq := strings.IndexAny(line, "=:")
		if eq <= 0 {
			a.add(rel, setbReasonKey, "第 "+strconv.Itoa(idx+1)+" 行缺少键值分隔", false)
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if !setbValidKey(key) {
			a.add(rel, setbReasonKey, "第 "+strconv.Itoa(idx+1)+" 行键非法", true)
			continue
		}
		keys[key]++
		if keys[key] > 1 {
			a.add(rel, setbReasonDup, key+" 重复定义", false)
		}
		value := line[eq+1:]
		if strings.Contains(value, "\\") && strings.Count(value, "\\")%2 == 1 {
			a.add(rel, setbReasonEsc, key+" 转义不完整", false)
		}
	}
	return a
}
