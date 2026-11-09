package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func fkNumber(props map[string]string, key string) (int, bool) {
	for _, candidate := range fkKeyVariants(key) {
		raw, ok := props[candidate]
		if !ok {
			continue
		}
		value, err := strconv.Atoi(strings.TrimSpace(strings.Trim(raw, `"'`)))
		if err != nil {
			return 0, false
		}
		return value, true
	}
	return 0, false
}

func fkBool(props map[string]string, key string) (bool, bool) {
	for _, candidate := range fkKeyVariants(key) {
		raw, ok := props[candidate]
		if !ok {
			continue
		}
		normalized := strings.ToLower(strings.TrimSpace(strings.Trim(raw, `"'`)))
		switch normalized {
		case "true", "yes", "on":
			return true, true
		case "false", "no", "off":
			return false, true
		}
		return false, false
	}
	return false, false
}

func fkString(props map[string]string, key string) (string, bool) {
	for _, candidate := range fkKeyVariants(key) {
		raw, ok := props[candidate]
		if !ok {
			continue
		}
		return strings.Trim(strings.TrimSpace(raw), `"'`), true
	}
	return "", false
}

func fkKeyVariants(key string) []string {
	normalized := strings.ToLower(key)
	return []string{
		normalized,
		"settings." + normalized,
		"world-settings.default." + normalized,
		"world-settings.default." + normalized,
	}
}

func fkInspectFile(a *ForkConfigAudit, dir, name string) bool {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	a.Files = append(a.Files, name)
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(name, fkReasonSymlink, "分支配置文件是符号链接", true)
		return true
	}
	if info.Size() > fkMaxConfigBytes {
		a.add(name, fkReasonTooLarge, "分支配置文件超过体积预算", true)
		return true
	}
	if info.Mode().Perm()&0o022 != 0 {
		a.add(name, fkReasonWorldWritable, "分支配置文件可被其他用户改写", true)
	}
	data, readErr := readBoundedFile(path, fkMaxConfigBytes)
	if readErr != nil {
		a.add(name, fkReasonUnreadable, "分支配置文件不可读", true)
		return true
	}
	fkScanText(a, name, string(data))
	return true
}
