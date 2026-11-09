package main

import (
	"os"
	"path/filepath"
	"strings"
)

func acInspectProperties(audit *AccessControlAudit, dir string) {
	path := filepath.Join(dir, "server.properties")
	body, err := readBoundedFile(path, acMaxJSONBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		audit.add("server.properties", acReasonUnreachable(err), "无法读取服务端属性", true)
		return
	}
	audit.Sources = append(audit.Sources, "server.properties")
	values := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		values[key] = strings.TrimSpace(line[eq+1:])
	}
	if mode, ok := values["online-mode"]; ok && strings.EqualFold(mode, "false") {
		audit.add("server.properties", acReasonOfflineMode, "online-mode=false 允许伪造用户名登录", true)
	}
	if white, ok := values["white-list"]; ok && strings.EqualFold(white, "false") {
		audit.add("server.properties", acReasonWhitelistOff, "白名单已关闭", false)
	}
	if enforce, ok := values["enforce-whitelist"]; ok && strings.EqualFold(enforce, "false") {
		audit.add("server.properties", acReasonWhitelistOff, "白名单未强制生效", false)
	} else if !ok {
		if white, ok2 := values["white-list"]; ok2 && strings.EqualFold(white, "true") {
			audit.add("server.properties", acReasonWhitelistOff, "启用白名单但未设置 enforce-whitelist", false)
		}
	}
}

func acReasonUnreachable(err error) string {
	if strings.Contains(err.Error(), "符号链接") {
		return acReasonSymlink
	}
	if strings.Contains(err.Error(), "体积") {
		return acReasonTooLarge
	}
	return acReasonUnreadable
}

func AuditServerAccessControl(serverDir string) AccessControlAudit {
	audit := AccessControlAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("", acReasonMissing, "服务器目录不存在", true)
		return audit
	}
	acInspectProperties(&audit, serverDir)
	acInspectOps(&audit, serverDir)
	acInspectWhitelist(&audit, serverDir)
	acInspectBans(&audit, serverDir, "banned-players.json")
	acInspectBans(&audit, serverDir, "banned-ips.json")
	if len(audit.Sources) == 0 {
		audit.add("", acReasonMissing, "未发现访问控制配置", false)
	}
	if len(audit.Findings) == 0 {
		audit.add("", acReasonOK, "访问控制配置未发现风险", false)
	}
	return audit
}
