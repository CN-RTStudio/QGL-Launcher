package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func hoScanHelp(audit *HelpOverrideAudit, rel, content string) {
	section := ""
	sectionIndent := -1
	topic := ""
	topicIndent := -1
	var topicBody strings.Builder
	permission := ""
	flush := func() {
		if topic != "" {
			hoAuditTopic(audit, rel, topic, topicBody.String())
			if permission != "" {
				for _, token := range strings.Split(permission, ",") {
					trimmed := strings.Trim(strings.TrimSpace(token), `"'`)
					if trimmed == "*" || strings.HasSuffix(trimmed, ".*") || trimmed == "bukkit.*" {
						audit.add(rel, topic, hoReasonWildcardPerm, "权限通配 "+trimmed, false)
					}
				}
			}
		}
		topic = ""
		topicBody.Reset()
		permission = ""
	}
	blockScalar := false
	blockIndent := -1
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimRight(raw, "\r")
		stripped := strings.TrimSpace(hoStripInlineComment(line))
		if stripped == "" {
			continue
		}
		indent := hoIndentOf(line)
		if blockScalar {
			if indent > blockIndent {
				topicBody.WriteString(strings.TrimSpace(line))
				topicBody.WriteString("\n")
				continue
			}
			blockScalar = false
		}
		if indent == 0 {
			flush()
			key := strings.ToLower(strings.TrimSuffix(strings.SplitN(stripped, ":", 2)[0], " "))
			known := false
			for _, candidate := range hoKnownSections {
				if key == candidate {
					known = true
					break
				}
			}
			if !known && key != "" {
				audit.add(rel, "", hoReasonBadSection, "未知顶层段落 "+key, false)
			}
			section = key
			sectionIndent = 0
			continue
		}
		if section == "" {
			audit.add(rel, "", hoReasonBadSection, "缩进内容缺少顶层段落", false)
			continue
		}
		if topic == "" || (sectionIndent >= 0 && indent == sectionIndent+2 && !strings.HasPrefix(stripped, "-")) {
			flush()
			topic = hoTopicName(stripped)
			topicIndent = indent
			if idx := strings.Index(stripped, ":"); idx >= 0 {
				live := strings.TrimSpace(stripped[idx+1:])
				if live != "" && live != "|-" && live != "|" && live != ">" {
					topicBody.WriteString(live)
				} else if strings.HasPrefix(live, "|") || strings.HasPrefix(live, ">") {
					blockScalar = true
					blockIndent = indent
				}
			}
			continue
		}
		if topic != "" && indent > topicIndent {
			key, value := stripped, ""
			if idx := strings.Index(stripped, ":"); idx >= 0 {
				key = strings.ToLower(strings.TrimSpace(stripped[:idx]))
				value = strings.TrimSpace(stripped[idx+1:])
			}
			knownField := false
			for _, field := range hoKnownFields {
				if key == field {
					knownField = true
					break
				}
			}
			if !knownField {
				audit.add(rel, topic, hoReasonUnknownField, "未知字段 "+key, false)
				continue
			}
			switch key {
			case "shorttext":
				if len(value) > hoMaxShortText {
					audit.add(rel, topic, hoReasonTextTooLong, fmt.Sprintf("短文本 %d 字符", len(value)), false)
				}
				topicBody.WriteString(value)
			case "fulltext":
				if strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">") {
					blockScalar = true
					blockIndent = indent
					continue
				}
				topicBody.WriteString(value)
			case "permission":
				permission = value
			}
			continue
		}
		if topic != "" {
			audit.add(rel, topic, hoReasonDuplicateKey, "主题字段层级异常", false)
		}
	}
	flush()
	if audit.Topics > hoMaxTopics {
		audit.add(rel, "", hoReasonTooManyTopics, fmt.Sprintf("帮助主题总数 %d", audit.Topics), true)
	}
}

func AuditServerHelpOverride(serverDir string) HelpOverrideAudit {
	audit := HelpOverrideAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("server", "", hoReasonMissing, "服务器目录不可用", false)
		return audit
	}
	for _, rel := range hoConfigCandidates {
		if !hoCheckFile(&audit, rel) {
			continue
		}
		data, readErr := readBoundedFile(filepath.Join(serverDir, filepath.FromSlash(rel)), hoMaxFileBytes)
		if readErr != nil {
			audit.add(rel, "", hoReasonUnreadable, readErr.Error(), false)
			continue
		}
		hoScanHelp(&audit, rel, string(data))
	}
	if audit.Topics == 0 {
		audit.add("help.yml", "", hoReasonOK, "未声明帮助覆盖", false)
	}
	return audit
}
