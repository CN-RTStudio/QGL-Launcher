package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
