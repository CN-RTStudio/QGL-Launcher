package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
