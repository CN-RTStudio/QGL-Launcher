package main

import "strings"

func caCheckFile(audit *CommandAliasAudit, rel string) bool {
	return checkServerCfgFile(audit.Dir, rel, caMaxFileBytes,
		cfgFileReasons{
			Missing:       caReasonMissing,
			Unreadable:    caReasonUnreadable,
			Symlink:       caReasonSymlink,
			TooLarge:      caReasonTooLarge,
			WorldWritable: caReasonWorldWritable,
			WorldReadable: caReasonWorldReadable,
		},
		cfgFileLabels{Noun: "配置文件", SizeLabel: "配置体积"},
		func(reason, detail string, blocking bool) { audit.add(rel, "", reason, detail, blocking) })
}
func caStripComment(line string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && i > 0 && (line[i-1] == ' ' || line[i-1] == '\t') {
				return line[:i]
			}
		}
	}
	return line
}
func caSplitValue(raw string) []string {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil
	}
	if strings.HasPrefix(text, "[") {
		text = strings.TrimSuffix(strings.TrimPrefix(text, "["), "]")
	}
	fields := strings.Split(text, ",")
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		token := strings.TrimSpace(field)
		token = strings.TrimPrefix(token, "-")
		token = strings.TrimSpace(token)
		token = strings.Trim(token, `"'`)
		if token != "" {
			out = append(out, token)
		}
	}
	return out
}
