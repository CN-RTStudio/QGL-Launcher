package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func skInspectFile(a *StartupSecretAudit, root, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	rel, relErr := filepath.Rel(root, path)
	if relErr != nil {
		rel = filepath.Base(path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(rel, skReasonSymlink, "启动脚本是符号链接", true)
		return
	}
	if info.Size() > skMaxFileBytes {
		a.add(rel, skReasonTooLarge, "启动脚本超过体积预算", true)
		return
	}
	if info.Mode().Perm()&0o022 != 0 {
		a.add(rel, skReasonWorldWritable, "启动脚本可被其他用户改写", true)
	}
	data, readErr := readBoundedFile(path, skMaxFileBytes)
	if readErr != nil {
		a.add(rel, skReasonUnreadable, "启动脚本不可读", true)
		return
	}
	a.Files = append(a.Files, rel)
	plain := skScanText(a, rel, string(data))
	if plain && info.Mode().Perm()&0o004 != 0 {
		a.add(rel, skReasonWorldReadable, "含凭据的启动脚本对其他用户可读", false)
	}
}

func skScanText(a *StartupSecretAudit, rel, text string) bool {
	plain := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "rem ") {
			continue
		}
		lower := strings.ToLower(line)
		if skLineHasSecret(lower) {
			a.add(rel, skReasonPlainSecret, "启动脚本包含明文口令赋值", true)
			plain = true
		}
		if skLineHasPropSecret(lower) {
			a.add(rel, skReasonPropSecret, "JVM 系统属性携带明文口令", true)
			plain = true
		}
		if skLineHasURLCreds(line) {
			a.add(rel, skReasonURLCreds, "启动脚本 URL 内嵌账号口令", true)
			plain = true
		}
		if strings.Contains(lower, "--accesstoken") || strings.Contains(lower, "-accesstoken") {
			a.add(rel, skReasonTokenArg, "命令行参数直接传递访问令牌", true)
			plain = true
		}
		if strings.Contains(lower, "rcon-cli") && (strings.Contains(lower, " -p ") || strings.Contains(lower, "--password")) {
			a.add(rel, skReasonRCONArg, "RCON 客户端参数携带明文口令", true)
			plain = true
		}
		if strings.HasPrefix(lower, "export ") || strings.HasPrefix(lower, "set ") || strings.HasPrefix(lower, "setx ") {
			if skLineHasSecret(lower) {
				a.add(rel, skReasonEnvSecret, "环境变量写入明文口令", true)
				plain = true
			}
		}
	}
	return plain
}

func skLineHasSecret(line string) bool {
	for _, key := range skSecretKeys {
		needle := key + "="
		idx := strings.Index(line, needle)
		if idx < 0 {
			continue
		}
		value := strings.TrimSpace(line[idx+len(needle):])
		value = strings.Trim(value, "\"'`")
		if value == "" || strings.HasPrefix(value, "$") || strings.HasPrefix(value, "%") {
			continue
		}
		if strings.HasPrefix(value, "${") || strings.HasPrefix(value, "<") {
			continue
		}
		return true
	}
	return false
}

func skLineHasPropSecret(line string) bool {
	if !strings.Contains(line, "-d") {
		return false
	}
	for _, key := range skSecretKeys {
		needle := key + "="
		idx := strings.Index(line, needle)
		if idx < 0 {
			continue
		}
		value := strings.TrimSpace(line[idx+len(needle):])
		value = strings.Trim(value, "\"'`")
		if value == "" || strings.HasPrefix(value, "$") || strings.HasPrefix(value, "%") || strings.HasPrefix(value, "${") {
			continue
		}
		return true
	}
	return false
}

func skLineHasURLCreds(line string) bool {
	idx := strings.Index(line, "://")
	if idx < 0 {
		return false
	}
	rest := line[idx+3:]
	at := strings.Index(rest, "@")
	if at <= 0 {
		return false
	}
	if strings.Index(rest[at:], "://") == 0 {
		return false
	}
	return strings.Contains(rest[:at], ":")
}

func AuditServerStartupSecrets(serverDir string) StartupSecretAudit {
	audit := StartupSecretAudit{Dir: serverDir}
	root, err := filepath.Abs(serverDir)
	if err != nil {
		audit.add("server-dir", skReasonUnreadable, "无法解析服务器目录", true)
		return audit
	}
	audit.Dir = root
	info, statErr := os.Lstat(root)
	if statErr != nil || !info.IsDir() {
		audit.add("server-dir", skReasonMissing, "服务器目录不存在", true)
		return audit
	}
	files := []string{}
	for _, name := range skScriptFiles {
		path := filepath.Join(root, name)
		if _, err := os.Lstat(path); err == nil {
			files = append(files, path)
		}
	}
	sort.Strings(files)
	if len(files) > skMaxFiles {
		files = files[:skMaxFiles]
	}
	for _, path := range files {
		skInspectFile(&audit, root, path)
	}
	if len(audit.Findings) == 0 {
		audit.add("startup", skReasonOK, "启动脚本均在凭据白名单外", false)
	}
	return audit
}
