package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func readBaselineStore(path string) (*baselineStore, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > baselineMaxBytes {
		return nil, fmt.Errorf("基线文件不是可信普通文件")
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return nil, err
	}
	var store baselineStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	if store.Version != baselineVersion || store.Files == nil {
		return nil, fmt.Errorf("基线版本不支持")
	}
	return &store, nil
}

func writeBaselineStore(path, serverDir string, hashes map[string]string) error {
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	store := baselineStore{Version: baselineVersion, ServerDir: serverDir, Files: hashes}
	return writePrivateJSONBounded(path, store, baselineMaxBytes)
}

func defaultConfigBaselinePath(serverDir string) (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("无法定位配置目录: %w", err)
	}
	canonical, err := canonicalAbs(serverDir)
	if err != nil {
		return "", fmt.Errorf("服务器目录无法归一: %w", err)
	}
	digest := NewUMFSHash()
	digest.Write([]byte(strings.ToLower(canonical)))
	name := hex.EncodeToString(digest.Sum(nil))
	return filepath.Join(root, "QingLongLauncher", "config-baseline", name+".json"), nil
}

func shortSum(sum string) string {
	if len(sum) <= 12 {
		return sum
	}
	return sum[:12]
}
