package main

import (
	"os"
	"path/filepath"
)

func lgInspectConfig(a *LogConfigAudit, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	rel, relErr := filepath.Rel(a.Dir, path)
	if relErr != nil {
		rel = filepath.Base(path)
	}
	a.Files = append(a.Files, rel)
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(rel, lgReasonSymlink, "日志配置是符号链接", true)
		return
	}
	if info.Size() > lgMaxConfigBytes {
		a.add(rel, lgReasonTooLarge, "日志配置超过体积预算", true)
		return
	}
	if info.Mode().Perm()&0o022 != 0 {
		a.add(rel, lgReasonWorldWritable, "日志配置可被其他用户改写", true)
	}
	data, err := readBoundedFile(path, lgMaxConfigBytes)
	if err != nil {
		a.add(rel, lgReasonUnreadable, "日志配置不可读", true)
		return
	}
	jndi, lookup, secret, remote, jdbc := lgScanConfigText(string(data))
	if jndi {
		a.add(rel, lgReasonJNDILookup, "日志配置包含 JNDI 查找表达式", true)
	}
	if lookup {
		a.add(rel, lgReasonEnvLookup, "日志配置使用运行时属性查找", false)
	}
	if secret {
		a.add(rel, lgReasonPlainSecret, "日志配置内写了明文口令", true)
	}
	if remote {
		a.add(rel, lgReasonRemoteAppender, "日志配置存在远程 appender", true)
	}
	if jdbc {
		a.add(rel, lgReasonJDBCTarget, "日志配置直连数据库写入", false)
	}
}
