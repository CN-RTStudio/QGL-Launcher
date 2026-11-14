package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var errIsolationPath = errors.New("路径越出允许的根目录")

func validateInstanceName(name string) error {
	if name == "" {
		return fmt.Errorf("实例名为空")
	}
	if len(name) > 64 {
		return fmt.Errorf("实例名超过 64 字节")
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("实例名含路径分隔符")
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("实例名含上跳片段")
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("实例名不得以点开头")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("实例名含控制字符")
		}
		if strings.ContainsRune(`:*?"<>|`, r) {
			return fmt.Errorf("实例名含 Windows 保留字符")
		}
	}
	return nil
}

func pathInsideRoot(root, target string) (string, error) {
	if root == "" || target == "" {
		return "", errIsolationPath
	}
	absRoot, rootErr := filepath.Abs(root)
	if rootErr != nil {
		return "", rootErr
	}
	absTarget, targetErr := filepath.Abs(target)
	if targetErr != nil {
		return "", targetErr
	}
	cleanRoot := filepath.Clean(absRoot)
	cleanTarget := filepath.Clean(absTarget)
	if cleanTarget == cleanRoot {
		return cleanTarget, nil
	}
	if !strings.HasPrefix(cleanTarget, cleanRoot+string(os.PathSeparator)) {
		return "", errIsolationPath
	}
	return cleanTarget, nil
}

func resolveInstanceDir(instancesRoot, instanceName string) (string, error) {
	if err := validateInstanceName(instanceName); err != nil {
		return "", err
	}
	if instancesRoot == "" {
		return "", errIsolationPath
	}
	candidate := filepath.Join(instancesRoot, instanceName)
	bound, boundErr := pathInsideRoot(instancesRoot, candidate)
	if boundErr != nil {
		return "", errIsolationPath
	}
	return bound, nil
}

func packResolveTarget(instancesRoot, targetName string) (string, error) {
	return resolveInstanceDir(instancesRoot, targetName)
}
