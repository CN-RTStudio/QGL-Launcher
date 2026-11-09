package main

import (
	"strings"
)

func (a *EnvHijackAudit) add(script, variable, reason, detail string, blocking bool) {
	if len(a.Findings) >= envMaxFindings {
		return
	}
	if len(detail) > envMaxInlineDetail {
		detail = detail[:envMaxInlineDetail] + "..."
	}
	a.Findings = append(a.Findings, EnvFinding{Script: script, Variable: variable, Reason: reason, Detail: detail, Blocking: blocking})
}

func envSplitAssignment(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	lower := strings.ToLower(line)
	for _, prefix := range []string{"export ", "set ", "setx "} {
		if strings.HasPrefix(lower, prefix) {
			line = strings.TrimSpace(line[len(prefix):])
			break
		}
	}
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "::") {
		return "", "", false
	}
	idx := strings.Index(line, "=")
	if idx <= 0 {
		return "", "", false
	}
	name := strings.TrimSpace(line[:idx])
	if name == "" || strings.ContainsAny(name, " \t\"'$") {
		return "", "", false
	}
	value := strings.TrimSpace(line[idx+1:])
	if strings.HasPrefix(value, `"`) || strings.HasPrefix(value, `'`) {
		value = strings.Trim(value, `"'`)
	}
	if value == "" {
		return "", "", false
	}
	return name, value, true
}

func envNameUpper(name string) string {
	if strings.HasPrefix(name, "%") && strings.HasSuffix(name, "%") {
		name = strings.Trim(name, "%")
	}
	return strings.ToUpper(strings.TrimSpace(name))
}

func envPathIsHijacked(value string) bool {
	lower := strings.ToLower(value)
	for _, token := range []string{"%.", ".%", "/tmp", "%temp%", "\\temp\\", ":./", ".;", "=.", "`"} {
		if strings.Contains(lower, strings.ToLower(token)) {
			return true
		}
	}
	for _, seg := range strings.Split(value, ":") {
		seg = strings.ToLower(strings.TrimSpace(seg))
		if seg == "." || seg == ".." || strings.HasPrefix(seg, "./") || strings.HasPrefix(seg, "../") {
			return true
		}
	}
	return false
}

func envValueHasAgent(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "-javaagent") || strings.Contains(lower, "-agentlib") || strings.Contains(lower, "-agentpath")
}
