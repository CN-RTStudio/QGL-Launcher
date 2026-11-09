package main

import (
	"os"
	"path/filepath"
)

type auditFileCheck struct {
	maxBytes            int64
	symlinkReason       string
	tooLargeReason      string
	worldWritableReason string
	unreadableReason    string
	symlinkDetail       string
	tooLargeDetail      string
	worldWritableDetail string
	unreadableDetail    string
}

func inspectAuditTextFile(add func(file, reason, detail string, blocking bool), files *[]string, root, path string, check auditFileCheck) (string, []byte, bool) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", nil, false
	}
	rel, relErr := filepath.Rel(root, path)
	if relErr != nil {
		rel = filepath.Base(path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		add(rel, check.symlinkReason, check.symlinkDetail, true)
		return rel, nil, false
	}
	if info.Size() > check.maxBytes {
		add(rel, check.tooLargeReason, check.tooLargeDetail, true)
		return rel, nil, false
	}
	if info.Mode().Perm()&0o022 != 0 {
		add(rel, check.worldWritableReason, check.worldWritableDetail, true)
	}
	data, readErr := readBoundedFile(path, check.maxBytes)
	if readErr != nil {
		add(rel, check.unreadableReason, check.unreadableDetail, true)
		return rel, nil, false
	}
	*files = append(*files, rel)
	return rel, data, true
}

var pmFileCheck = auditFileCheck{
	maxBytes:            pmMaxFileBytes,
	symlinkReason:       pmReasonSymlink,
	tooLargeReason:      pmReasonTooLarge,
	worldWritableReason: pmReasonWorldWritable,
	unreadableReason:    pmReasonUnreadable,
	symlinkDetail:       "权限配置是符号链接",
	tooLargeDetail:      "权限配置超过体积预算",
	worldWritableDetail: "权限配置可被其他用户改写",
	unreadableDetail:    "权限配置不可读",
}

var yhFileCheck = auditFileCheck{
	maxBytes:            yhMaxBytes,
	symlinkReason:       yhReasonSymlink,
	tooLargeReason:      yhReasonTooLarge,
	worldWritableReason: yhReasonWorldWritable,
	unreadableReason:    yhReasonUnreadable,
	symlinkDetail:       "YAML 配置是符号链接",
	tooLargeDetail:      "YAML 配置超过体积预算",
	worldWritableDetail: "YAML 配置可被其他用户改写",
	unreadableDetail:    "YAML 配置不可读",
}
