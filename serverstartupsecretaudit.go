package main

import (
	"os"
	"path/filepath"
)

const (
	skReasonOK            = "ok"
	skReasonSymlink       = "symlink"
	skReasonTooLarge      = "too-large"
	skReasonWorldWritable = "world-writable"
	skReasonWorldReadable = "world-readable"
	skReasonUnreadable    = "unreadable"
	skReasonPlainSecret   = "plaintext-secret"
	skReasonPropSecret    = "system-property-secret"
	skReasonURLCreds      = "url-credentials"
	skReasonTokenArg      = "token-argument"
	skReasonRCONArg       = "rcon-password-argument"
	skReasonEnvSecret     = "env-secret"
	skReasonMissing       = "missing"

	skMaxFileBytes = 256 << 10
	skMaxFiles     = 16
	skMaxFindings  = 48
)

var skScriptFiles = []string{
	"start.sh",
	"start.bat",
	"start.cmd",
	"run.sh",
	"run.bat",
	"run.cmd",
	"launch.sh",
	"launch.bat",
	"launch.cmd",
	"user_jvm_args.txt",
	"jvm.args",
	"server.args",
}

var skSecretKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"apikey",
	"api-key",
	"api_key",
	"accesskey",
	"access-key",
	"rcon.password",
	"rcon-password",
}

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
