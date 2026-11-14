package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type PropDupFinding = auditFinding
type PropDupAudit struct {
	ServerDir string
	Findings  []PropDupFinding
}

func (a *PropDupAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spxMaxFindings, PropDupFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PropDupAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PropDupFinding) bool { return f.Blocking })
}

func (a *PropDupAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PropDupAudit) Describe() string {
	return describeReasonDetail("属性文件键结构未发现重复或畸形", a.Findings, 12)
}

func spxEntry(index int, key, value string) string {
	if len(value) > 40 {
		value = value[:40] + "…"
	}
	return fmt.Sprintf("第 %d 行 %s=%s", index, key, value)
}

func AuditServerPropertiesStructure(serverDir string) *PropDupAudit {
	a := &PropDupAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(spxMiss, "未配置服务器目录", false)
		return a
	}
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(spxMiss, "缺少 server.properties", false)
		return a
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(spxRead, err.Error(), true)
		return a
	}
	if link {
		a.add(spxLink, "属性文件是符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, spxMaxFile)
	if err != nil {
		a.add(spxRead, err.Error(), true)
		return a
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	lines := strings.Split(text, "\n")
	firstSeen := map[string]int{}
	foldedSeen := map[string]string{}
	keys := 0
	for i, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		index := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			a.add(spxMalformed, fmt.Sprintf("第 %d 行缺少等号，整行被忽略", index), false)
			continue
		}
		key := line[:eq]
		value := line[eq+1:]
		keys++
		if key == "" {
			a.add(spxEmptyKey, fmt.Sprintf("第 %d 行的键为空", index), true)
			continue
		}
		if strings.TrimSpace(key) != key {
			a.add(spxKeySpace, fmt.Sprintf("第 %d 行的键带首尾空白", index), false)
		}
		if len(value) > 2048 {
			a.add(spxLongValue, fmt.Sprintf("第 %d 行的值长度 %d 异常", index, len(value)), false)
		}
		if strings.Contains(value, "#") && !strings.HasPrefix(strings.TrimSpace(value), "#") {
			a.add(spxInlineHash, fmt.Sprintf("第 %d 行的值含 #，不是注释而是字面内容", index), false)
		}
		if prev, ok := firstSeen[key]; ok {
			a.add(spxDupKey, fmt.Sprintf("%s 与第 %d 行重复", spxEntry(index, key, value), prev), true)
		} else {
			firstSeen[key] = index
		}
		folded := strings.ToLower(key)
		if prev, ok := foldedSeen[folded]; ok && prev != key {
			a.add(spxCaseDup, fmt.Sprintf("第 %d 行 %s 与 %s 仅大小写不同", index, key, prev), true)
		} else if !ok {
			foldedSeen[folded] = key
		}
	}
	if keys == 0 {
		a.add(spxEmpty, "属性文件没有任何有效键值", false)
	}
	if keys > spxMaxKeys {
		a.add(spxTooManyKeys, fmt.Sprintf("键数量 %d 超出上限 %d", keys, spxMaxKeys), false)
	}
	return a
}
