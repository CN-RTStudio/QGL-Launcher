package main

import (
	"os"
	"path/filepath"
	"strings"
)

func auditProxySecretFile(audit *ServerProxyAudit, serverDir string) string {
	path := filepath.Join(serverDir, "forwarding.secret")
	info, err := os.Lstat(path)
	if err != nil {
		audit.Findings = append(audit.Findings, ProxyFinding{File: "forwarding.secret", Reason: proxyReasonSecretMissing, Detail: "Velocity 需要转发密钥文件", Blocking: false})
		return ""
	}
	audit.Files = append(audit.Files, "forwarding.secret")
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, ProxyFinding{File: "forwarding.secret", Reason: proxyReasonSecretSymlink, Detail: "密钥文件是符号链接", Blocking: true})
		return ""
	}
	if info.Mode().Perm()&0o044 != 0 {
		audit.Findings = append(audit.Findings, ProxyFinding{File: "forwarding.secret", Reason: proxyReasonSecretPermissive, Detail: "同机其他账户可读该密钥", Blocking: false})
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		audit.Findings = append(audit.Findings, ProxyFinding{File: "forwarding.secret", Reason: proxyReasonUnreadable, Detail: "密钥文件不可读", Blocking: false})
		return ""
	}
	return strings.TrimSpace(string(data))
}

func AuditServerProxyTrust(serverDir string) *ServerProxyAudit {
	audit := &ServerProxyAudit{}
	if strings.TrimSpace(serverDir) == "" {
		audit.Findings = append(audit.Findings, ProxyFinding{Reason: proxyReasonMissing, Detail: "未提供服务器目录"})
		return audit
	}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		audit.Findings = append(audit.Findings, ProxyFinding{Reason: proxyReasonMissing, Detail: "服务器目录不存在"})
		return audit
	}

	props := map[string]string{}
	propsPath := filepath.Join(serverDir, "server.properties")
	if data, reason := readProxyConfig(propsPath); reason == "" {
		audit.Files = append(audit.Files, "server.properties")
		props = proxyProperties(data)
	} else if reason != proxyReasonMissing {
		audit.Findings = append(audit.Findings, ProxyFinding{File: "server.properties", Reason: reason, Detail: "服务器主配置不可用", Blocking: reason == proxyReasonSymlink})
	}

	yamlCandidates := []string{"spigot.yml", "paper-global.yml", filepath.Join("config", "paper-global.yml")}
	yamlMaps := map[string]map[string]string{}
	for _, name := range yamlCandidates {
		data, reason := readProxyConfig(filepath.Join(serverDir, name))
		if reason == proxyReasonMissing {
			continue
		}
		audit.Files = append(audit.Files, name)
		if reason != "" {
			audit.Findings = append(audit.Findings, ProxyFinding{File: name, Reason: reason, Detail: "代理配置文件不可用", Blocking: reason == proxyReasonSymlink || reason == proxyReasonTooLarge})
			continue
		}
		flat, dups := flattenYAML(data)
		for _, d := range dups {
			audit.Findings = append(audit.Findings, ProxyFinding{File: name, Key: d, Reason: proxyReasonDuplicateKey, Detail: "重复的配置键，最终值取决于解析器", Blocking: false})
		}
		yamlMaps[name] = flat
	}

	bungeeEnabled := false
	velocityEnabled := false
	velocitySecret := ""
	for name, flat := range yamlMaps {
		if strings.EqualFold(flat["settings.bungeecord"], "true") {
			bungeeEnabled = true
			audit.Findings = append(audit.Findings, ProxyFinding{File: name, Key: "settings.bungeecord", Value: "true", Reason: proxyReasonLegacyBungee, Detail: "旧式 BungeeCord 转发", Blocking: false})
		}
		if strings.EqualFold(flat["proxies.bungee-cord.online-mode"], "true") {
			bungeeEnabled = true
		}
		if strings.EqualFold(flat["proxies.velocity.enabled"], "true") {
			velocityEnabled = true
			if v, ok := flat["proxies.velocity.secret"]; ok {
				velocitySecret = v
			}
		}
	}

	audit.ProxyEnabled = bungeeEnabled || velocityEnabled
	if velocityEnabled {
		if audit.Provider == "" {
			audit.Provider = "velocity"
		}
	} else if bungeeEnabled {
		audit.Provider = "bungeecord"
	}

	if !audit.ProxyEnabled {
		audit.Findings = append(audit.Findings, ProxyFinding{Reason: proxyReasonOK, Detail: "未启用代理转发"})
		return audit
	}

	bind := props["server-ip"]
	bindSafe := isLoopbackBind(bind)
	if !bindSafe {
		detail := "后端绑定非回环地址，可绕过代理直连"
		if isWildcardBind(bind) {
			detail = "后端监听通配地址，可绕过代理直连伪造身份"
		}
		audit.Findings = append(audit.Findings, ProxyFinding{File: "server.properties", Key: "server-ip", Value: bind, Reason: proxyReasonProxyExposed, Detail: detail, Blocking: true})
	}

	if strings.EqualFold(props["online-mode"], "false") && !bindSafe {
		audit.Findings = append(audit.Findings, ProxyFinding{File: "server.properties", Key: "online-mode", Value: "false", Reason: proxyReasonOnlineModeOff, Detail: "后端关闭正版验证且监听可直连地址，身份校验被完全绕过", Blocking: true})
	}

	if velocityEnabled {
		secret := velocitySecret
		if secret == "" {
			secret = auditProxySecretFile(audit, serverDir)
		}
		reason, detail, blocking := proxySecretVerdict(secret)
		if reason != proxyReasonOK {
			audit.Findings = append(audit.Findings, ProxyFinding{File: "forwarding.secret", Key: "proxies.velocity.secret", Value: secret, Reason: reason, Detail: detail, Blocking: blocking})
		}
	}

	return audit
}
