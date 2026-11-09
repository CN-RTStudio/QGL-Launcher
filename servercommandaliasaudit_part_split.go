package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func caScanCommands(audit *CommandAliasAudit, rel, content string) {
	inAliases := false
	aliasesIndent := -1
	current := ""
	pending := []string{}
	flush := func() {
		if current != "" {
			caAuditAlias(audit, rel, current, pending)
		}
		current = ""
		pending = nil
	}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimRight(caStripComment(raw), "\r")
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := 0
		for indent < len(line) && (line[indent] == ' ' || line[indent] == '\t') {
			indent++
		}
		text := strings.TrimSpace(line)
		if strings.HasPrefix(text, "\t") {
			continue
		}
		if indent == 0 {
			flush()
			key := strings.TrimSuffix(strings.SplitN(text, ":", 2)[0], " ")
			inAliases = strings.EqualFold(key, "aliases")
			aliasesIndent = 0
			if !inAliases && !strings.EqualFold(key, "aliases") {
				switch strings.ToLower(key) {
				case "aliases", "default-permissions", "aliases-file":
				default:
					if len(audit.Findings) < caMaxFindings {
						audit.add(rel, "", caReasonUnknownSection, "未知顶层段落 "+key, false)
					}
				}
			}
			continue
		}
		if !inAliases {
			continue
		}
		if aliasesIndent < 0 {
			aliasesIndent = indent
		}
		if current != "" && strings.HasPrefix(text, "-") {
			targets := caSplitValue(strings.TrimSpace(strings.TrimPrefix(text, "-")))
			pending = append(pending, targets...)
			continue
		}
		if current != "" && indent > aliasesIndent {
			if len(audit.Findings) < caMaxFindings {
				audit.add(rel, current, caReasonBadIndent, "别名目标缩进异常", false)
			}
			continue
		}
		flush()
		if aliasesIndent < 0 || (aliasesIndent == 0 && indent > 0) {
			aliasesIndent = indent
		}
		if strings.HasPrefix(text, "-") {
			if len(audit.Findings) < caMaxFindings {
				audit.add(rel, "", caReasonBadIndent, "别名段落出现游离列表项", false)
			}
			continue
		}
		name := text
		if idx := strings.Index(text, ":"); idx >= 0 {
			name = strings.TrimSpace(text[:idx])
			live := caSplitValue(text[idx+1:])
			pending = append(pending, live...)
		}
		current = strings.Trim(name, `"'`)
	}
	flush()
	if audit.Aliases > caMaxAliases {
		audit.add(rel, "", caReasonTooManyAlias, fmt.Sprintf("同名别名总数 %d", audit.Aliases), true)
	}
}

func AuditServerCommandAliases(serverDir string) CommandAliasAudit {
	audit := CommandAliasAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("server", "", caReasonMissing, "服务器目录不可用", false)
		return audit
	}
	for _, rel := range caConfigCandidates {
		if !caCheckFile(&audit, rel) {
			continue
		}
		data, readErr := readBoundedFile(filepath.Join(serverDir, filepath.FromSlash(rel)), caMaxFileBytes)
		if readErr != nil {
			audit.add(rel, "", caReasonUnreadable, readErr.Error(), false)
			continue
		}
		caScanCommands(&audit, rel, string(data))
	}
	if audit.Aliases == 0 {
		audit.add("commands.yml", "", caReasonOK, "未声明命令别名", false)
	}
	return audit
}
