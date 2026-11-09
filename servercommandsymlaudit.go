package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	scyMaxFindings = 32
	scyMaxFile     = 256 * 1024
	scyMaxAliases  = 64
	scyReasonMiss  = "missing"
	scyReasonLink  = "symlink"
	scyReasonLarge = "too-large"
	scyReasonRead  = "unreadable"
	scyReasonEmpty = "empty-config"
	scyReasonName  = "invalid-alias-name"
	scyReasonMeth  = "alias-without-command"
	scyReasonChain = "command-chaining"
	scyReasonPriv  = "privileged-alias"
	scyReasonCtl   = "control-characters"
	scyReasonMany  = "too-many-aliases"
)

type CommandsYmlFinding = auditFinding

type CommandsYmlAudit struct {
	ServerDir string
	Findings  []CommandsYmlFinding
}

type commandsYmlBlock struct {
	Name     string
	Commands []string
}

func (a *CommandsYmlAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= scyMaxFindings {
		return
	}
	a.Findings = append(a.Findings, CommandsYmlFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *CommandsYmlAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CommandsYmlFinding) bool { return f.Blocking })
}

func (a *CommandsYmlAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *CommandsYmlAudit) Describe() string {
	return describeAuditFindings("服务器命令别名配置未发现风险", a.Findings, 12,
		func(f CommandsYmlFinding) []string {
			return []string{f.File, f.Reason, f.Detail}
		},
		func(f CommandsYmlFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

func scyValidAliasName(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	if value[0] >= '0' && value[0] <= '9' {
		return false
	}
	for _, c := range value {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func scyCollectAliases(text string) []commandsYmlBlock {
	blocks := make([]commandsYmlBlock, 0, 8)
	var current *commandsYmlBlock
	inSection := false
	for _, line := range strings.Split(text, "\n") {
		raw := strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent == 0 {
			inSection = trimmed == "aliases:" || strings.HasPrefix(trimmed, "aliases: ")
			current = nil
			continue
		}
		if !inSection {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			if current == nil {
				continue
			}
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			value = cfgStripQuotes(value)
			if strings.HasPrefix(value, "#") {
				continue
			}
			value = strings.TrimSpace(cfgStripInlineComment(value))
			if value != "" {
				current.Commands = append(current.Commands, value)
			}
			continue
		}
		if strings.HasSuffix(trimmed, ":") {
			name := cfgStripQuotes(strings.TrimSuffix(trimmed, ":"))
			current = &commandsYmlBlock{Name: name}
			blocks = append(blocks, *current)
			current = &blocks[len(blocks)-1]
		}
	}
	return blocks
}

func scyHasControlChars(text string) bool {
	return hasControlCharsText(text)
}

func AuditServerCommandsYml(serverDir string) *CommandsYmlAudit {
	a := &CommandsYmlAudit{ServerDir: serverDir}
	const rel = "commands.yml"
	if serverDir == "" {
		a.add(".", scyReasonMiss, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", scyReasonLink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, scyReasonLink, "命令别名配置为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, scyMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, scyReasonLarge, fmt.Sprintf("命令别名配置超过 %d 字节", scyMaxFile), true)
			return a
		}
		a.add(rel, scyReasonRead, "命令别名配置不可读", false)
		return a
	}
	text := string(data)
	if scyHasControlChars(text) {
		a.add(rel, scyReasonCtl, "配置文件含控制字符", true)
	}
	blocks := scyCollectAliases(text)
	if len(blocks) == 0 {
		a.add(rel, scyReasonEmpty, "未解析到任何命令别名", false)
		return a
	}
	if len(blocks) > scyMaxAliases {
		a.add(rel, scyReasonMany, fmt.Sprintf("别名数量 %d 超过 %d", len(blocks), scyMaxAliases), false)
	}
	for _, block := range blocks {
		if !scyValidAliasName(block.Name) {
			a.add(rel, scyReasonName, "别名 "+block.Name+" 名称非法", true)
		}
		if len(block.Commands) == 0 {
			a.add(rel, scyReasonMeth, "别名 "+block.Name+" 没有可执行命令", false)
			continue
		}
		for _, command := range block.Commands {
			if strings.ContainsAny(command, ";|&\x00\r\n") {
				a.add(rel, scyReasonChain, "别名 "+block.Name+" 含命令连接符", true)
				continue
			}
			head := strings.ToLower(strings.TrimSpace(command))
			fields := strings.Fields(head)
			if len(fields) == 0 {
				continue
			}
			switch fields[0] {
			case "op", "deop", "stop", "restart", "reload":
				a.add(rel, scyReasonPriv, "别名 "+block.Name+" 指向高权限命令 "+head, true)
				continue
			}
			if strings.HasPrefix(head, "whitelist off") || strings.HasPrefix(head, "ban-ip") {
				a.add(rel, scyReasonPriv, "别名 "+block.Name+" 指向高权限命令 "+head, true)
			}
		}
	}
	return a
}
