package main

import (
	"fmt"
	"strings"
)

func hoStripInlineComment(text string) string {
	lower := strings.ToLower(text)
	for _, marker := range []string{" #", "\t#"} {
		if idx := strings.Index(lower, marker); idx >= 0 {
			return text[:idx]
		}
	}
	return text
}

func hoTopicName(raw string) string {
	name := strings.TrimSpace(raw)
	name = strings.TrimSuffix(name, ":")
	return strings.Trim(name, `"'`)
}

func hoAuditTopic(audit *HelpOverrideAudit, rel, name, body string) {
	audit.Topics++
	clean := strings.ToLower(strings.TrimSpace(name))
	if clean == "" {
		audit.add(rel, name, hoReasonEmptyTopic, "帮助主题名为空", false)
		return
	}
	for _, builtin := range hoBuiltinTopics {
		if clean == builtin {
			audit.add(rel, name, hoReasonShadowTopic, "覆盖内置帮助主题 "+builtin, false)
			return
		}
	}
	if len(body) > hoMaxFullText {
		audit.add(rel, name, hoReasonTextTooLong, fmt.Sprintf("主题文本 %d 字符", len(body)), true)
	}
	if hoHasControlRune(body) {
		audit.add(rel, name, hoReasonControlChars, "主题文本含控制字符", true)
	}
	if hoHasRemoteURL(body) {
		audit.add(rel, name, hoReasonRemoteURL, "主题文本含外部链接", false)
	}
	if strings.Contains(body, "\u00a7") {
		audit.add(rel, name, hoReasonUnknownField, "主题文本含格式化转义", false)
	}
}
