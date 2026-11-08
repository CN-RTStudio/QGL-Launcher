package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	caReasonOK             = "ok"
	caReasonMissing        = "missing"
	caReasonUnreadable     = "unreadable"
	caReasonSymlink        = "symlink"
	caReasonTooLarge       = "too-large"
	caReasonWorldWritable  = "world-writable"
	caReasonWorldReadable  = "world-readable"
	caReasonCatchAll       = "catch-all-alias"
	caReasonShadowed       = "shadowed-command"
	caReasonInternalTarget = "internal-target"
	caReasonTooManyAlias   = "too-many-aliases"
	caReasonBadName        = "bad-alias-name"
	caReasonDuplicate      = "duplicate-alias"
	caReasonVariableTarget = "variable-target"
	caReasonEmptyTarget    = "empty-target"
	caReasonBadIndent      = "bad-indent"
	caReasonUnknownSection = "unknown-section"

	caMaxFileBytes = 1 << 20
	caMaxAliases   = 64
	caMaxTargets   = 8
	caMaxFindings  = 48
)

var caConfigCandidates = []string{
	"commands.yml",
	"config/commands.yml",
}

var caPrivilegedCommands = []string{
	"op",
	"deop",
	"stop",
	"restart",
	"ban",
	"ban-ip",
	"pardon",
	"pardon-ip",
	"whitelist",
	"kick",
	"save-off",
	"save-all",
	"reload",
	"plugins",
	"permissions",
}

var caAliasNamePattern = regexp.MustCompile(`^/?[A-Za-z0-9_.:-]{1,48}$`)

type CommandAliasFinding struct {
	File     string
	Alias    string
	Reason   string
	Detail   string
	Blocking bool
}

type CommandAliasAudit struct {
	Dir      string
	Findings []CommandAliasFinding
	Aliases  int
}

func (a CommandAliasAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a CommandAliasAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != caReasonOK {
			return true
		}
	}
	return false
}

func (a CommandAliasAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == caReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail))
		if len(parts) >= caMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务器命令别名未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *CommandAliasAudit) add(file, alias, reason, detail string, blocking bool) {
	if len(a.Findings) >= caMaxFindings {
		return
	}
	a.Findings = append(a.Findings, CommandAliasFinding{
		File:     file,
		Alias:    alias,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}

func caCheckFile(audit *CommandAliasAudit, rel string) bool {
	path := filepath.Join(audit.Dir, filepath.FromSlash(rel))
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			audit.add(rel, "", caReasonMissing, "配置文件不存在", false)
		} else {
			audit.add(rel, "", caReasonUnreadable, err.Error(), false)
		}
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(rel, "", caReasonSymlink, "配置文件是符号链接", true)
		return false
	}
	if !info.Mode().IsRegular() {
		audit.add(rel, "", caReasonUnreadable, "配置文件不是普通文件", true)
		return false
	}
	if info.Size() > caMaxFileBytes {
		audit.add(rel, "", caReasonTooLarge, fmt.Sprintf("配置体积 %d 字节", info.Size()), true)
		return false
	}
	if info.Mode().Perm()&0o022 != 0 {
		audit.add(rel, "", caReasonWorldWritable, fmt.Sprintf("权限 %#o 允许他人写入", info.Mode().Perm()), true)
	}
	if info.Mode().Perm()&0o004 != 0 {
		audit.add(rel, "", caReasonWorldReadable, fmt.Sprintf("权限 %#o 允许他人读取", info.Mode().Perm()), false)
	}
	return true
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
