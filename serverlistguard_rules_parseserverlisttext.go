package main

import (
	"strconv"
	"strings"
)

func ParseServerListText(text string, lim ServerListLimits) ([]ServerEntry, []string) {
	d := lim.withDefaults()
	if hasControlCharStr(text) {
		text = strings.Map(func(r rune) rune {
			if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
				return -1
			}
			return r
		}, text)
	}
	lines := strings.Split(text, "\n")
	if len(lines) > d.MaxLines {
		lines = lines[:d.MaxLines]
	}
	entries := make([]ServerEntry, 0, len(lines))
	var errs []string
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 尝试切分名称与地址：最后一个空白或竖线。
		name, addr := splitServerLine(line)
		if addr == "" {
			addr = line
			name = ""
		}
		entry, err := ParseServerAddress(addr, d)
		if err != nil {
			errs = append(errs, "line rejected: "+err.Error())
			continue
		}
		entry.Name = SanitizeServerName(name, d)
		entries = append(entries, entry)
	}
	return entries, errs
}

func splitServerLine(line string) (name, addr string) {
	if i := strings.LastIndexByte(line, '|'); i >= 0 {
		return line[:i], line[i+1:]
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		return strings.Join(fields[:len(fields)-1], " "), fields[len(fields)-1]
	}
	return "", line
}

// SummarizeServerEntries 输出一行审计摘要。
func SummarizeServerEntries(entries []ServerEntry, errs []string) string {
	var sb strings.Builder
	sb.WriteString("serverlist parsed entries=")
	sb.WriteString(strconv.Itoa(len(entries)))
	if len(errs) > 0 {
		sb.WriteString(" errors=")
		sb.WriteString(strconv.Itoa(len(errs)))
	}
	return sb.String()
}
