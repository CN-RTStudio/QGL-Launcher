package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

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

const (
	spxMaxFindings = 18
	spxMaxFile     = 256 * 1024
	spxMaxKeys     = 512
	spxMaxDetail   = 8
	spxMiss        = "properties-missing"
	spxRead        = "properties-unreadable"
	spxLink        = "properties-symlink"
	spxEmpty       = "properties-empty"
	spxMalformed   = "properties-line-malformed"
	spxDupKey      = "properties-duplicate-key"
	spxCaseDup     = "properties-case-duplicate"
	spxEmptyKey    = "properties-empty-key"
	spxKeySpace    = "properties-key-whitespace"
	spxInlineHash  = "properties-inline-comment"
	spxTooManyKeys = "properties-key-count"
	spxLongValue   = "properties-value-too-long"
)
