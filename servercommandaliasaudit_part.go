package main

import (
	"fmt"
	"strings"
)

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

func caNormalizeAlias(name string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "/"))
}

func caTargetCommand(target string) string {
	cmd := strings.ToLower(strings.TrimSpace(target))
	cmd = strings.TrimPrefix(cmd, "/")
	if idx := strings.IndexAny(cmd, " \t"); idx >= 0 {
		cmd = cmd[:idx]
	}
	return cmd
}

func caAuditAlias(audit *CommandAliasAudit, rel, name string, targets []string) {
	audit.Aliases++
	clean := caNormalizeAlias(name)
	if clean == "*" || clean == "**" || strings.HasSuffix(clean, ":*") {
		audit.add(rel, name, caReasonCatchAll, "别名匹配全部命令", true)
		return
	}
	if !caAliasNamePattern.MatchString(strings.TrimSpace(name)) {
		audit.add(rel, name, caReasonBadName, "别名包含非法字符或超长", false)
	}
	for _, priv := range caPrivilegedCommands {
		if clean == priv {
			audit.add(rel, name, caReasonShadowed, "覆盖了受保护命令 "+priv, true)
			return
		}
	}
	if len(targets) == 0 {
		audit.add(rel, name, caReasonEmptyTarget, "别名没有目标命令", false)
		return
	}
	if len(targets) > caMaxTargets {
		audit.add(rel, name, caReasonTooManyAlias, fmt.Sprintf("单别名包含 %d 个目标", len(targets)), false)
	}
	seen := map[string]bool{}
	for _, target := range targets {
		cmd := caTargetCommand(target)
		if cmd == "" {
			continue
		}
		if seen[cmd] {
			audit.add(rel, name, caReasonDuplicate, "别名重复指向 "+cmd, false)
		}
		seen[cmd] = true
		if strings.ContainsAny(cmd, "$%{}") {
			audit.add(rel, name, caReasonVariableTarget, "别名目标含变量占位"+cmd, false)
		}
		if strings.HasPrefix(cmd, "bukkit:") || strings.HasPrefix(cmd, "minecraft:") {
			audit.add(rel, name, caReasonInternalTarget, "别名直指内部命令 "+cmd, true)
			continue
		}
		for _, priv := range caPrivilegedCommands {
			if cmd == priv {
				audit.add(rel, name, caReasonShadowed, "别名放行受保护命令 "+cmd, true)
			}
		}
	}
}
